import re
import matplotlib.pyplot as plt
import numpy as np

# Initialize a list to store the number of services for each user
service_counts = []

# Open the file and process each line
with open('userdata2.txt', 'r') as file:
    for line in file:
        # Check for the service count line (starts with "s:")
        match = re.match(r'^s:(\d+)$', line.strip())
        if match:
            # Extract the number of services and add to the list
            service_counts.append(int(match.group(1)))

# Calculate average and spread (standard deviation)
average_services = np.mean(service_counts)
spread_services = np.std(service_counts)

# Print the average and spread
print(f"Average number of services per user: {average_services:.2f}")
print(f"Spread (standard deviation) of services per user: {spread_services:.2f}")

# Create a histogram of the service counts
plt.hist(service_counts, bins=range(1, max(service_counts)+2), edgecolor='black', align='left')
plt.title(f'Distribution of Number of Services per User\n(Avg: {average_services:.2f}, Spread: {spread_services:.2f})')
plt.xlabel('Number of Services')
plt.ylabel('Number of Users')
plt.xticks(range(1, max(service_counts)+1))
plt.grid(axis='y')

# Show the plot
plt.show()