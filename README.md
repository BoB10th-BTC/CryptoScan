# CryptoScan (Volatility 3 Plugin)
## Made by
BTC (BoB Tracers of Coin)
`강정윤` `박준성` `이문규` `임민택` `정현덕`
## How it works
### Volatility Command
```
python ./vol.py -f [memory.mem] windows.cryptoscan --pid [Process ID] --[btc,eth,xrp] [--pdf]
```
### Example
```python .\vol.py -f sample.mem windows.cryptoscan --pid --btc --pdf```
- `--[btc,eth,xrp]`: Types of cryptocurrency that you want to extract transactions from.
- `--pdf`: Export the output result to a PDF file.
