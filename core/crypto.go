package core

// RecoverSignerFromSignBytes return address who signs the signature
func RecoverSignerFromSignBytes(signer []byte) (*Address, error) {
	addr, err := NewAddressFromPublicKey(signer)
	if err != nil {
		return nil, err
	}
	return addr, nil
}
