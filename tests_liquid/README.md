# End-to-end tests

These tests are implemented in Python and can be executed either using the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a Ledger Nano S/X/SP.

All the commands in this folder are meant to be ran from the `tests` folder, not from the root.

Python dependencies are listed in [requirements.txt](requirements.txt), install them using [pip](https://pypi.org/project/pip/)

```
pip install -r requirements.txt
```

## Launch with Speculos

Build the app as normal from the root folder. For convenience, you probably want to enable DEBUG:

```
COIN=liquid_regtest DEBUG=1 make
```

Then run all the tests from this folder, specifying the device: nanos, nanox, nanosp, or all:

```
pytest --device yourdevice
```
You can enable the screen display with the option `--display`

## Launch with your Nano S/X/SP

Compile and install the app on your device as normal.

To run the tests on your Ledger device you also need to install an optional dependency

```
pip install ledgercomm[hid]
```

Be sure to have you device connected through USB (without any other software interacting with it) and run

```
pytest --device yourdevice --backend ledgercomm
```
