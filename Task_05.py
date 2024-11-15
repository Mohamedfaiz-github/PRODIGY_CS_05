from scapy.all import sniff
import pandas as pd
import matplotlib.pyplot as plt

# Initialize a list to store packet details
packet_data = []

# Callback function to process each packet
def process_packet(packet):
    try:
        # Extract relevant details from the packet
        source_ip = packet[0][1].src if hasattr(packet[0][1], 'src') else "N/A"
        destination_ip = packet[0][1].dst if hasattr(packet[0][1], 'dst') else "N/A"
        protocol = packet[0][1].proto if hasattr(packet[0][1], 'proto') else "N/A"
        payload = bytes(packet[0][1].payload).decode(errors='ignore') if packet[0][1].payload else "N/A"
        
        # Append data to the list
        packet_data.append({
            "Source IP": source_ip,
            "Destination IP": destination_ip,
            "Protocol": protocol,
            "Payload": payload
        })

        # Print packet details (optional)
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 50)
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing packets (requires admin/root privileges)
def start_sniffing():
    print("Starting packet capture... Press Ctrl+C to stop.")
    sniff(prn=process_packet, filter="ip", store=0, count=50)  # Captures 50 packets

# Analyze and visualize captured packets
def analyze_packets():
    if not packet_data:
        print("No packets captured.")
        return

    # Convert packet data to a pandas DataFrame
    df = pd.DataFrame(packet_data)

    # Save data to a CSV file
    df.to_csv("captured_packets.csv", index=False)
    print("Captured packet data saved to 'captured_packets.csv'.")

    # Count occurrences of each protocol
    protocol_counts = df['Protocol'].value_counts()

    # Plot protocol distribution
    plt.figure(figsize=(10, 6))
    protocol_counts.plot(kind='bar', color='skyblue')
    plt.title('Protocol Frequency')
    plt.xlabel('Protocol')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    try:
        start_sniffing()
        analyze_packets()
    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")
        analyze_packets()
    except Exception as e:
        print(f"An error occurred: {e}")
