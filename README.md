# Yoshi Packet Sniffer

Yoshi Packet Sniffer is a Python application that allows you to capture and analyze network packets. It uses the Scapy library for packet sniffing and tkinter for the graphical user interface.

## Features

- Capture network packets and display them in a treeview.
- Copy the source IP:Port, destination IP:Port, and protocol of selected packets to the clipboard.
- Start and stop packet capturing.

## Installation

1. Clone the repository

2. Install the required dependencies:

    ```shell
    pip install scapy tkinter pyperclip
    ```

## Usage

1. Run the `main.py` file:

    ```shell
    python main.py
    ```

2. Click on the "Start Capture" button to start capturing packets.
3. Right-click on a packet in the treeview to copy its details to the clipboard.
4. Click on the "Stop Capture" button to stop capturing packets.

## Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
