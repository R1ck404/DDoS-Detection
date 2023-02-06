import os, statistics, time, logging, re

# Set up the logger
logger = logging.getLogger('attack_detector')
logger.setLevel(logging.DEBUG)

# Create a handler to log to the console
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# Set the format for the log messages
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%m/%d/%Y %I:%M:%S%p')
ch.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(ch)

# Set interval for when the program should check
sleep_interval = 15

# Set threshold for number of connections
connection_threshold = 1000

# Initialize list to store previous number of connections
previous_connections = []

while True:
    # Check for increased network activity
    result = os.popen("netstat -an | FindStr /R /C:\":80 \" | find /C /V \"\"").readline()
    connections = int(result.strip())
    previous_connections.append(connections)

    os.system('title DDoS Attack Detector : Connnections: {}'.format(str(connections)))
    # Use statistical analysis to determine if the network activity is abnormal
    if len(previous_connections) >= 10:
        mean = statistics.mean(previous_connections)
        stddev = statistics.stdev(previous_connections)

        # Send a warning if the number of connections is above the threshold and significantly higher than average
        if connections > connection_threshold and connections > (mean + 2 * stddev):
            logger.warning('Potential DDoS Attack [c=' + format(connections) + ']')
            previous_connections = []
        else:
            logger.debug('Connections are normal [c=' + format(connections) + ']')
            previous_connections.pop(0)
    else:
        logger.debug('Not enough data to determine normal connection amount [c=' + format(connections) + ']')

    # Check again in the entered amount of seconds
    time.sleep(sleep_interval)
