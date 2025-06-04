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
uv run src/privkey_to_walletaddr.py <32bytes_privateKey>
> 🔑 Private Key: <32bytes_privateKey>
> Bitcoin Legacy (P2PKH): 1G5Bg6w4srw965M1JSYTFNtDg4fXpeYh3r
> Bitcoin Nested Segwit (P2SH-P2WPKH): 38VbMvBDJFAdoYPRQXdb4hWACuHHerAzjr
> Bitcoin Native Segwit (P2WPKH): bc1q5428vq2uzwhm3taey9sr9x5vm6tk78ew0wt525
> Bitcoin Native Segwit (P2WSH): bc1qeh0tmlq629phhdvh5j3xhezv0aax8nzd8ar9def2cx0gq97nvgtsh8her7
> Bitcoin Native Segwit v1 (P2TR): bc1psvv9xk65zpw5574wvrqgl3zlj6r3sx60mlrzt0g6w5l6wwtla46spgks55
> Ethereum Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
> Tron Address: TYBNgWfhGuNzdLtjKtxXTfskAhTbMcqbaG
```
