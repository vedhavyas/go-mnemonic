# go-mnemonic
    
Reference implementation of a mnemonic code or mnemonic sentence -- a group of easy to remember words -- for the generation of deterministic wallets.

## BIP Paper

See https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki for full specification

## Usage
```go
import "github.com/vedhavyas/go-mnemonic"
```

#### func  GenerateEntropy

```go
func GenerateEntropy(strength int) ([]byte, error)
```
GenerateEntropy returns entropy with strength, given strength taken from
pre-defined list

#### func  ToMnemonic

```go
func ToMnemonic(entropy []byte, wordListPath string) (words []string, err error)
```
ToMnemonic returns mnemonic words from entropy. If wordListPath is empty, default list specified in bip-39 is used

#### func  ToSeed

```go
func ToSeed(words []string, password string) string
```
ToSeed returns the seed from the given mnemonic words and password
