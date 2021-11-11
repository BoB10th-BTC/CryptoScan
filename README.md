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

![image](https://user-images.githubusercontent.com/49504937/141319492-aab159a3-4a07-453c-8446-3f3198bc06f8.png)
- `--pdf`: Export the output result to a PDF file.

![image](https://user-images.githubusercontent.com/49504937/141319559-65f90594-23a1-4dbb-8f8e-a668e273b3da.png)

