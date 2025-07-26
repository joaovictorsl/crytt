package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func main() {
	// Default values
	broker := "tcp://localhost:1883"
	topic := "test/topic"
	clientID := "go-mqtt-subscriber"

	// Parse command-line arguments
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-broker":
			if i+1 < len(os.Args) {
				broker = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -broker requires a value.")
				os.Exit(1)
			}
		case "-topic":
			if i+1 < len(os.Args) {
				topic = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -topic requires a value.")
				os.Exit(1)
			}
		case "-clientid":
			if i+1 < len(os.Args) {
				clientID = os.Args[i+1]
				i++
			} else {
				fmt.Println("Error: -clientid requires a value.")
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
	opts.SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
		fmt.Printf("Received message: %s from topic: %s\n", msg.Payload(), msg.Topic())
	})
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		fmt.Println("Connected to MQTT broker!")
		token := client.Subscribe(topic, 1, nil) // QoS 1
		token.Wait()
		if token.Error() != nil {
			fmt.Printf("Error subscribing to topic %s: %v\n", topic, token.Error())
			return
		}
		fmt.Printf("Subscribed to topic: %s\n", topic)
	})
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

	// Keep the program running until interrupted
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("Disconnecting from MQTT broker...")
	client.Disconnect(250) // Disconnect with a 250ms quiet period
	fmt.Println("Disconnected.")
}

func printUsage() {
	fmt.Println("Usage: go run main.go [-broker <broker_address>] [-topic <topic_name>] [-clientid <client_id>]")
	fmt.Println("  -broker    MQTT broker address (e.g., tcp://localhost:1883)")
	fmt.Println("  -topic     MQTT topic to subscribe to")
	fmt.Println("  -clientid  MQTT client ID")
	fmt.Println("  -h, --help  Show this help message")
}
