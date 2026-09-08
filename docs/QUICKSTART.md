# Sweep BTCB2 with two computers and a USB drive

Use `BTCB2-Offline.exe` on the computer holding your wallet. Use `BTCB2-Online.exe` on a different computer with internet access. Version 0.1.0 is a prerelease that completed an [internal review and cross-review](AUDIT.md), with no independent external security audit or full-node validation. Read `SECURITY.md` before using real funds.

## Set up once

1. Download the **Offline** and **Online** Windows x64 ZIPs from the repository's [Releases page](https://github.com/ZenulAbidin/btcb2-offline-sweeper/releases). Use the matching version for both computers.
2. Extract the Online ZIP on the connected computer. Copy the Offline ZIP to the disconnected computer and extract it there. Copying an app does not require copying your wallet.
3. Keep the signing computer disconnected from Wi-Fi, Ethernet and other network connections. The offline app has no online workflow, but the operating system must also remain offline.
4. Confirm that your receiving address belongs to a wallet or service supporting **BTCB2 / BLAKE2b**. An address that looks like a Bitcoin address does not prove that the receiver supports this fork.
5. Use a clearly named USB folder such as `BTCB2 transfer`. Leave your original wallet and backup on the offline computer. Never put the wallet, seed phrase, password or private-key export in that transfer folder.

## Use the menus

Double-click an EXE to open its terminal interface. Use the arrow keys to select an item, Tab to move between controls, and Enter to continue. The file browser lets you choose drives, folders and files without typing commands. Cancel returns to the menu; completed files can be reopened. Save files with recognizable names so you can reopen them after restarting an app.

## 1. Offline: export public addresses

Open the offline app and choose the option to export a public inventory. Select your wallet source:

- **Electrum wallet file:** browse to your wallet on the offline computer and enter its password if required.
- **BIP39 recovery phrase:** enter the phrase only on the offline computer, and select the matching address type and account. The BIP39 passphrase is a separate secret, not necessarily your wallet app password.
- **WIF / Bitcoin Core export:** browse to a compressed private-key text export kept on the offline computer.

Select a receiving and change address range large enough to cover your wallet's history; a small range can miss funds. Enter a receiving address you already know from your original wallet; the wizard checks that this address is in the exported range. Different accounts and BIP44/BIP84 types need separate scans. Save **public_inventory.json** to USB and move the USB to the online computer. Keep this exact public file; signing needs it later.

## 2. Online: find BTCB2 coins

Open the online app and choose **2. Find my BTCB2 funds from the public address list**. Browse to the inventory on USB, confirm the BTCB2 explorer, and choose where to save the returned fork-data folder. Start the scan.

Review the results, including excluded outputs. No coins found can mean an insufficient address range, the wrong account/type/passphrase, already-spent fork coins, or a failed explorer request. Do not assume a zero result proves the wallet has no fork funds.

Move the entire returned **fork-data folder**, along with your original public inventory, back to the offline computer. Keep the folder intact, including **manifest.json** and **verification.json**. Raw parent transactions are embedded in the manifest; you do not need to fetch or edit any file. Bring the destination address and your chosen BTCB2 fee rate for the offline review step.

## 3. Offline: review and sign

Choose **3. Open the returned funds file, review and sign**, then open **manifest.json** inside the fork-data folder. Enter your BTCB2 destination, chosen fee rate in sat/vB, and per-transaction and total fee limits. Choose where to save the unsigned review plan. Check the complete destination against a separately trusted copy, plus the input total, amount being sent and fee.

Open the original **public_inventory.json** and load the same wallet source. The wizard verifies that the wallet controls the requested outputs. Choose an offline folder for the signed result. Signing requires explicit destination confirmation. After signing, use the guided export to choose a USB folder; only the validated **report.json** and transaction **.hex** files are copied. Take that entire **signed folder** to the online computer. No coins have been sent yet.

## 4. Online: review and broadcast

Choose **4. Review signed files and broadcast**, then select the signed folder. Check its destination, amount, fee and transaction IDs. Confirm the explorer and select a local folder for receipts. Confirm broadcasting only when the displayed details are correct and the receiver supports BTCB2.

Keep **receipts.json** and use **Check transaction status from a saved receipt** to check confirmation. A connection timeout after broadcasting can mean the network accepted a transaction but the response was lost. To continue, reopen the same signed folder and choose the existing receipt folder; the app checks uncertain results before attempting remaining transactions. Saving or signing alone does not move coins.

## If you need to stop

Cancel or close the app and keep the last files it successfully saved. **Open a saved plan and sign** resumes from an unsigned **report.json**, its matching manifest, and the original public inventory. **Export a signed result to USB** repeats a validated export. Do not make replacement copies of wallet secrets for the online computer. If your wallet is not a supported type, read **wallet-compatibility.md**; renaming a backup file does not convert it.
