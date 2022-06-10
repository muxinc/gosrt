// Copyright 2020 FOSS GmbH. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	"github.com/datarhei/gosrt/internal/packet"

	"github.com/benburkert/openpgp/aes/keywrap"
	"golang.org/x/crypto/pbkdf2"
)

type Crypto interface {
	GenerateSEK(key packet.PacketEncryption) error
	UnmarshalKM(km *packet.CIFKM, passphrase string) error
	MarshalKM(km *packet.CIFKM, passphrase string, key packet.PacketEncryption) error
	EncryptOrDecryptPayload(data []byte, key packet.PacketEncryption, packetSequenceNumber uint32) error
}

type crypto struct {
	salt      []byte
	keyLength int

	evenSEK []byte
	oddSEK  []byte
}

func New(keyLength int) (Crypto, error) {
	// 3.2.2.  Key Material
	switch keyLength {
	case 16:
	case 24:
	case 32:
	default:
		return nil, fmt.Errorf("crypto: invalid key size, must be either 16, 24, or 32")
	}

	c := &crypto{
		keyLength: keyLength,
	}

	// 3.2.2.  Key Material: "The only valid length of salt defined is 128 bits."
	c.salt = make([]byte, 16)
	if err := c.prng(c.salt); err != nil {
		return nil, fmt.Errorf("crypto: can't generate salt: %w", err)
	}

	c.evenSEK = make([]byte, c.keyLength)
	if err := c.GenerateSEK(packet.EvenKeyEncrypted); err != nil {
		return nil, err
	}

	c.oddSEK = make([]byte, c.keyLength)
	if err := c.GenerateSEK(packet.OddKeyEncrypted); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *crypto) GenerateSEK(key packet.PacketEncryption) error {
	if !key.IsValid() {
		return fmt.Errorf("crypto: unknown key type")
	}

	if key == packet.EvenKeyEncrypted {
		if err := c.prng(c.evenSEK); err != nil {
			return fmt.Errorf("crypto: can't generate even key: %w", err)
		}
	} else if key == packet.OddKeyEncrypted {
		if err := c.prng(c.oddSEK); err != nil {
			return fmt.Errorf("crypto: can't generate odd key: %w", err)
		}
	}

	return nil
}

func (c *crypto) UnmarshalKM(km *packet.CIFKM, passphrase string) error {
	if len(km.Salt) != 0 {
		copy(c.salt, km.Salt)
	}

	kek := c.calculateKEK(passphrase)

	unwrap, err := keywrap.Unwrap(kek, km.Wrap)
	if err != nil {
		return err
	}

	n := 1
	if km.KeyBasedEncryption == packet.EvenAndOddKey {
		n = 2
	}

	if len(unwrap) != n*c.keyLength {
		return fmt.Errorf("crypto: the unwrapped key has the wrong length")
	}

	if km.KeyBasedEncryption == packet.EvenKeyEncrypted {
		copy(c.evenSEK, unwrap)
	} else if km.KeyBasedEncryption == packet.OddKeyEncrypted {
		copy(c.oddSEK, unwrap)
	} else {
		copy(c.evenSEK, unwrap[:c.keyLength])
		copy(c.oddSEK, unwrap[c.keyLength:])
	}

	return nil
}

func (c *crypto) MarshalKM(km *packet.CIFKM, passphrase string, key packet.PacketEncryption) error {
	if key == packet.UnencryptedPacket || !key.IsValid() {
		return fmt.Errorf("crypto: invalid key for encryption. Must be even or odd or both")
	}

	km.S = 0
	km.Version = 1
	km.PacketType = 2
	km.Sign = 0x2029
	km.KeyBasedEncryption = key // even or odd key
	km.KeyEncryptionKeyIndex = 0
	km.Cipher = 2
	km.Authentication = 0
	km.StreamEncapsulation = 2
	km.SLen = 16
	km.KLen = uint16(c.keyLength)

	if len(km.Salt) != 16 {
		km.Salt = make([]byte, 16)
	}
	copy(km.Salt, c.salt)

	n := 1
	if key == packet.EvenAndOddKey {
		n = 2
	}

	w := make([]byte, n*c.keyLength)

	if key == packet.EvenKeyEncrypted {
		copy(w, c.evenSEK)
	} else if key == packet.OddKeyEncrypted {
		copy(w, c.oddSEK)
	} else {
		copy(w[:c.keyLength], c.evenSEK)
		copy(w[c.keyLength:], c.oddSEK)
	}

	kek := c.calculateKEK(passphrase)

	wrap, err := keywrap.Wrap(kek, w)
	if err != nil {
		return err
	}

	if len(km.Wrap) != len(wrap) {
		km.Wrap = make([]byte, len(wrap))
	}

	copy(km.Wrap, wrap)

	return nil
}

func (c *crypto) EncryptOrDecryptPayload(data []byte, key packet.PacketEncryption, packetSequenceNumber uint32) error {
	// 6.1.2.  AES Counter
	//    0   1   2   3   4   5  6   7   8   9   10  11  12  13  14  15
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	// |                   0s                  |      psn      |  0   0|
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	//                            XOR
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	// |                    MSB(112, Salt)                     |
	// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	//
	// psn    (32 bit): packet sequence number
	// ctr    (16 bit): block counter, all zeros
	// nonce (112 bit): 14 most significant bytes of the salt
	//
	// CTR = (MSB(112, Salt) XOR psn) << 16

	ctr := make([]byte, 16)

	binary.BigEndian.PutUint32(ctr[10:], packetSequenceNumber)

	for i := range ctr[:14] {
		ctr[i] ^= c.salt[i]
	}

	var sek []byte
	if key == packet.EvenKeyEncrypted {
		sek = c.evenSEK
	} else if key == packet.OddKeyEncrypted {
		sek = c.oddSEK
	} else {
		return fmt.Errorf("crypto: invalid SEK selected. Must be either even or odd")
	}

	// 6.2.2.  Encrypting the Payload
	// 6.3.2.  Decrypting the Payload
	block, err := aes.NewCipher(sek)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, ctr)
	stream.XORKeyStream(data, data)

	return nil
}

func (c *crypto) calculateKEK(passphrase string) []byte {
	// 6.1.4.  Key Encrypting Key (KEK)
	return pbkdf2.Key([]byte(passphrase), c.salt[8:], 2048, c.keyLength, sha1.New)
}

func (c *crypto) prng(p []byte) error {
	n, err := rand.Read(p)
	if err != nil {
		return err
	}

	if n != len(p) {
		return fmt.Errorf("crypto: random byte sequence is too short")
	}

	return nil
}