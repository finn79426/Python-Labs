# Python-Labs

Just another repo stored bunch of my shitty code.

## Authentication

### Get 2FA OTP

```shell=
uv run src/2fa_otp_generate.py <2FA_SECRET>
> 2FA Secret Key: <2FA_SECRET>
> 2FA OTP Code: 807318

# Or by setting a env variable
export TWO_FA_SECRET='<2FA_SECRET>'
uv run src/2fa_otp_generate.py
> 2FA Secret Key: <2FA_SECRET>
> 2FA OTP Code: 807318
```


## Blockchain

### Convert private key to wallet address

```shell=
uv run src/privkey_to_walletaddr.py <64bytes_privateKey>
> Private Key: <64bytes_privateKey>
> Ethereum Address: 0x71562b71999873DB5b286dF957af199Ec94617F7
> Tron Address: TLJUauqE7WkhRoccujvnqH62tk66AtT6Zf
```
