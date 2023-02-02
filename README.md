# Attack Detector
Attack Detector is a tool that can help defend your computer against cyber attacks, specifically Distributed Denial of Service (DDoS) attacks. This tool will periodically monitor the number of connections to your computer and raise an alert if the number of connections exceeds a threshold, indicating a potential DDoS attack.

## Features
- Periodically monitors the number of connections to your computer.
- Uses statistical analysis to determine if the number of connections is significantly higher than average.
- Raises an alert if a potential DDoS attack is detected.
- Logs the alerts to the console for easy viewing.


## Requirements
- Python 3.x


## Usage
1. Clone the repository to your computer.
2. Install the required libraries by running the following command:
```bash
  pip install -r requirements.txt
```

3. Run the script by executing the following command:
```bash
  python DDoSDetector.py
```
4. The tool will start monitoring the number of connections to your computer and logging any alerts to the console.
    
## Customization
- You can adjust the threshold value for the number of connections that triggers an alert by changing the 'connection_threshold' variable in the code.
- You can change the interval at which the tool checks the number of connections by changing the 'sleep_interval' variable in the code.

## Limitations
- The tool only monitors incoming connections to your computer, not outgoing connections.
- The tool relies on the netstat command to get the number of connections, which may not be available on all operating systems.
- The tool uses a simple statistical analysis to determine if the number of connections is significantly higher than average, which may not be suitable for all use cases.

## Contributing
Contributions are always welcome!
If you would like to contribute to the project, please submit a pull request or open an issue for discussion.
