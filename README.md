# ORB v1.3 - Post-Quantum Encrypted Voice Chat

ORB is a secure, peer-to-peer voice chat application with post-quantum encryption capabilities. It features Kyber512 key exchange for establishing secure sessions and AES-256-GCM for encrypted audio transmission.

## Features

- 🎙️ Real-time voice communication
- 🔒 Post-quantum encryption using Kyber512
- 🌐 Peer-to-peer networking (UDP)
- 🖥️ Host or join voice channels
- 🎚️ Audio device selection
- 📊 Visual activity indicators
- 🧑‍🤝‍🧑 Participant list management
- 🚀 NAT traversal assistance

## Requirements

- Python 3.7+
- Windows, macOS, or Linux
- Microphone and speakers/headphones

## Installation

1. First, install the required dependencies:
```bash
pip install tkinter pyaudio pycryptodome pqcrypto==0.1.0
```
Note: On some systems, you may need to install tkinter separately:

- Debian/Ubuntu:
```bash
sudo apt-get install python3-tk
```
- Fedora:
```bash
sudo dnf install python3-tkinter
```

2. Clone this repository or download the source file:

```bash
git clone https://github.com/lewallen4/orb.git
cd orb
```

## Usage

Run the application with:

```bash
python orb_host.py
```

### Hosting a Channel

1. Run "HOST ORB"
2. Share your IP address and port with others

### Joining a Channel

1. Run "CLIENT ORB"
2. Enter the host's IP address and port
3. Enter your display name
4. Click "CONNECT"

### Controls

- Spacebar: Push-to-talk (hold to transmit)
- Click ORB: Toggle transmit mode
- Test Audio: Verify your audio devices work
- Toggle Encryption: Enable/disable encryption (default: on)

## Encryption Details

ORB uses a hybrid encryption scheme:

1. Key Exchange: Kyber512 (post-quantum secure) for establishing shared secrets
2. Audio Encryption: AES-256-GCM for encrypting the audio stream
3. Key Rotation: Session keys are rotated periodically (default: 60 seconds)

When encryption is enabled:
- All key exchanges use Kyber512
- Audio data is encrypted with AES-256-GCM
- Each participant has unique session keys
- Keys are derived using SHA-256 from the Kyber shared secret

## Troubleshooting

### Common Issues

1. No audio devices found:
   - Verify your microphone/speakers are connected
   - Check system audio settings
   - Try different audio devices in the configuration

2. Connection problems:
   - Verify firewall settings allow UDP traffic on the selected port
   - Try using a different port if the default is blocked
   - For internet connections, ensure port forwarding is set up if behind NAT

3. Encryption errors:
   - Ensure all participants have encryption enabled/disabled consistently
   - Try toggling encryption off if experiencing connection issues

### Logs

The application creates an orb.log file with detailed debug information for troubleshooting.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This is experimental software. While it implements strong encryption, no guarantee of complete security is provided. Use at your own risk.
