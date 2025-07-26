package main

import (
	"fmt"
	"os"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func main() {
	// Default values
	broker := "tcp://localhost:1883"
	topic := "test/topic"
	message := "Hello from Go Publisher!"
	qos := byte(1) // Quality of Service: 0, 1, or 2
	clientID := "go-mqtt-publisher"

	// Parse command-line arguments
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-broker":
			if i+1 < len(os.Args) {
				broker = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -broker requires a value.")
				printUsage()
				os.Exit(1)
			}
		case "-topic":
			if i+1 < len(os.Args) {
				topic = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -topic requires a value.")
				printUsage()
				os.Exit(1)
			}
		case "-message":
			if i+1 < len(os.Args) {
				message = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -message requires a value.")
				printUsage()
				os.Exit(1)
			}
		case "-qos":
			if i+1 < len(os.Args) {
				q := os.Args[i+1]
				if q == "0" {
					qos = 0
				} else if q == "1" {
					qos = 1
				} else if q == "2" {
					qos = 2
				} else {
					fmt.Printf("Error: Invalid QoS value '%s'. Must be 0, 1, or 2.\n", q)
					printUsage()
					os.Exit(1)
				}
				i++
			} else {
				fmt.Println("Error: -qos requires a value.")
				printUsage()
				os.Exit(1)
			}
		case "-clientid":
			if i+1 < len(os.Args) {
				clientID = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -clientid requires a value.")
				printUsage()
				os.Exit(1)
			}
		case "-h", "--help":
			printUsage()
			os.Exit(0)
		default:
			fmt.Printf("Unknown argument: %s\n", os.Args[i])
			printUsage()
			os.Exit(1)
		}
	}

	// MQTT Client Options
	opts := mqtt.NewClientOptions()
	opts.AddBroker(broker)
	opts.SetClientID(clientID)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		fmt.Printf("Connection lost: %v\n", err)
	})
	opts.SetReconnectingHandler(func(client mqtt.Client, opts *mqtt.ClientOptions) {
		fmt.Println("Attempting to reconnect...")
	})

	// Create a new MQTT client
	client := mqtt.NewClient(opts)

	// Connect to the broker
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		fmt.Printf("Failed to connect to broker: %v\n", token.Error())
		os.Exit(1)
	}
	fmt.Println("Connected to MQTT broker.")

	// Publish the message
	fmt.Printf("Publishing message '%s' to topic '%s' with QoS %d...\n", message, topic, qos)
	token := client.Publish(topic, qos, false, message) // false means not retained
	token.Wait()
	if token.Error() != nil {
		fmt.Printf("Failed to publish message: %v\n", token.Error())
		client.Disconnect(250)
		os.Exit(1)
	}

	fmt.Println("Message published successfully.")

	// Disconnect after publishing
	client.Disconnect(250)
	fmt.Println("Disconnected from MQTT broker.")
}

func printUsage() {
	fmt.Println("Usage: go run publisher.go [-broker <broker_address>] [-topic <topic_name>] [-message <message_string>] [-qos <0|1|2>] [-clientid <client_id>]")
	fmt.Println("  -broker    MQTT broker address (e.g., tcp://localhost:1883)")
	fmt.Println("  -topic     MQTT topic to publish to")
	fmt.Println("  -message   The message string to publish")
	fmt.Println("  -qos       Quality of Service (0, 1, or 2). Default is 1.")
	fmt.Println("  -clientid  MQTT client ID")
	fmt.Println("  -h, --help  Show this help message")
}
