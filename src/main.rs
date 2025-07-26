use base64::{Engine as _, engine::general_purpose};
use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::Serializer;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, Read, Write},
};

mod crypto;
use aes_gcm::{
    AeadCore, Aes256Gcm, Key,
    aead::{AeadMutInPlace, KeyInit, OsRng},
};
use crypto::ecdsa::EcdsaKeyPair;
use crypto::rsa::RsaKeyPair;
use crypto::{ecdsa, rsa};

use ::rsa::{Oaep, RsaPublicKey, pkcs1::EncodeRsaPublicKey, signature::SignerMut};
use mosquitto_rs::{Client, ConnectionStatus, Event, QoS}; // Import QoS
use p256::ecdsa::signature::Verifier; // You might need to import Signature and Verifier traits
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc::{Receiver, Sender};

const RSA_SIZE: usize = 2048;
const RSA_SKEY_FILE: &str = "rsa_key";
const RSA_PKEY_FILE: &str = "rsa_key.pub";
const RSA_TARGETS_PKEY_FOLDER: &str = "targets_rsa";
const ECDSA_SKEY_FILE: &str = "ecdsa_key";
const ECDSA_PKEY_FILE: &str = "ecdsa_key.pub";
const ECDSA_TARGETS_PKEY_FOLDER: &str = "targets_ecdsa";

const TOPIC_REVOKE: &str = "jvsl/sisdef/broadcast/revogacao";
const TOPIC_BROADCAST_KEYS: &str = "jvsl/sisdef/broadcast/chaves";
const TOPIC_DM: &str = "jvsl/sisdef/direto";

#[derive(Debug, Clone)]
enum Command {
    PublishIdentity(String),
    Refresh,
    RequestRevoke(String, String),
    SendMessage(String, String),
    ReloadPublicKeys,
    MqttAddPublicKey(PublicIdentityMessage),
    RevokeKey(RevokeMessage),
    Quit,
}

#[derive(Debug)]
enum CommandOutput {
    State(State),
    Error(String),
}

#[derive(Debug)]
enum MqttCommand {
    Publish {
        topic: String,
        payload: String,
        qos: QoS,
        retain: bool,
    },
    Subscribe {
        topic: String,
        qos: QoS,
    },
    // Could add more for disconnect, etc.
}

#[derive(Debug, Clone)]
struct State {
    pub rsa_key_pair: RsaKeyPair,
    pub ecdsa_key_pair: EcdsaKeyPair,
}

impl State {
    fn new(rsa_key_pair: RsaKeyPair, ecdsa_key_pair: EcdsaKeyPair) -> Self {
        State {
            rsa_key_pair,
            ecdsa_key_pair,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RevokeContent {
    unidade_revogada: String,
    timestamp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct RevokeMessage {
    remetente: String,
    revogacao: RevokeContent,
    assinatura_b64: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RevokedKeys {
    revoked: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PublicIdentityMessage {
    id_unidade: String,
    chave_publica_rsa: String,
    chave_publica_eddsa: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (ui_tx, mut ui_rx) = tokio::sync::mpsc::channel(32);
    let (background_tx, background_rx) = tokio::sync::mpsc::channel(32);
    let background_tx_clone = background_tx.clone();
    // NEW: Channel for MQTT commands
    let (mqtt_tx, mut mqtt_rx) = tokio::sync::mpsc::channel(32);

    // 1. MQTT Handler Task
    let mqtt_broker_address = "test.mosquitto.org";
    let mqtt_broker_port = 1883;

    let mqtt_handle = tokio::spawn(async move {
        let client = Client::with_auto_id().expect("Failed to create Mosquitto client");
        let subscriptions = client
            .subscriber()
            .expect("Failed to get subscriber handle");

        let mut is_connected = false;
        loop {
            // Attempt to connect if not connected
            if !is_connected {
                println!(
                    "Attempting connection to Mosquitto at {}:{}",
                    mqtt_broker_address, mqtt_broker_port
                );
                match client
                    .connect(
                        mqtt_broker_address,
                        mqtt_broker_port,
                        std::time::Duration::from_secs(5),
                        None, // No user data for now
                    )
                    .await
                {
                    Ok(_) => {
                        is_connected = true;
                        println!("Connection to Mosquitto successful: {:?}", is_connected);
                        if let Err(e) = client.subscribe(TOPIC_REVOKE, QoS::ExactlyOnce).await {
                            eprintln!("Failed to subscribe to {}: {:?}", TOPIC_REVOKE, e);
                        }
                        println!("{}", format!("subscribed to: {}", TOPIC_REVOKE));
                        if let Err(e) = client
                            .subscribe(
                                format!("{}/+", TOPIC_BROADCAST_KEYS).as_str(),
                                QoS::ExactlyOnce,
                            )
                            .await
                        {
                            eprintln!(
                                "Failed to subscribe to {}: {:?}",
                                format!("{}/+", TOPIC_BROADCAST_KEYS),
                                e
                            );
                        }
                        println!("{}", format!("subscribed to: {}/+", TOPIC_BROADCAST_KEYS));
                    }
                    Err(e) => {
                        eprintln!("Failed to connect to Mosquitto: {:?}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await; // Wait before retrying
                        continue;
                    }
                }
            }

            tokio::select! {
                // Handle incoming MQTT messages
                Ok(evt) = subscriptions.recv() => {
                    match evt {
                        Event::Message(msg) => {
                            if msg.topic == TOPIC_REVOKE {
                                match serde_json::from_slice(msg.payload.as_slice()) {
                                    Ok(data) => {
                                        background_tx_clone.send(Command::RevokeKey(data)).await.unwrap();
                                    },
                                    Err(_) => println!("Failed to parse broadcast keys json to struct"),
                                }
                            } else if msg.topic.split_at(TOPIC_BROADCAST_KEYS.len()).0 == TOPIC_BROADCAST_KEYS {
                                println!("{}", String::from_utf8(msg.clone().payload).unwrap());
                                match serde_json::from_slice(msg.payload.as_slice()) {
                                    Ok(data) => {
                                        background_tx_clone.send(Command::MqttAddPublicKey(data)).await.unwrap();
                                    },
                                    Err(_) => println!("Failed to parse broadcast keys json to struct"),
                                }
                            }
                            // Handle other messages here
                        }
                        Event::Connected(status) => {
                            is_connected = true;
                            println!("MQTT Client Event: Connected: {:?}", is_connected);
                        }
                        Event::Disconnected(reason_code) => {
                            is_connected = false;
                            println!("MQTT Client Event: Disconnected: {:?}. Attempting reconnect...", reason_code);
                            // The outer loop will handle reconnection after a small delay
                        }
                    }
                },
                // Handle commands from other tasks (e.g., publish requests)
                Some(cmd) = mqtt_rx.recv() => {
                    match cmd {
                        MqttCommand::Publish { topic, payload, qos, retain } => {
                            if is_connected {
                                println!("MQTT Handler: Publishing to '{}'", topic);
                                if let Err(e) = client.publish(topic, payload, qos, retain).await {
                                    eprintln!("MQTT Handler: Failed to publish: {:?}", e);
                                    // You might send an error back to the origin if needed
                                }
                            } else {
                                is_connected = false;
                                eprintln!("MQTT Handler: Cannot publish, not connected.");
                                // You might queue messages or send an error back
                            }
                        },
                        MqttCommand::Subscribe { topic, qos } => {
                            if is_connected {
                                println!("MQTT Handler: Subscribing to '{}'", topic);
                                if let Err(e) = client.subscribe(&topic, qos).await {
                                    eprintln!("MQTT Handler: Failed to subscribe: {:?}", e);
                                }
                            } else {
                                is_connected = false;
                                eprintln!("MQTT Handler: Cannot subscribe, not connected.");
                            }
                        },
                    }
                },
                else => break,
            }
        }
    });

    let background_tx_clone = background_tx.clone();
    let background_handle = tokio::spawn(async move {
        // Pass mqtt_tx into the background function
        background(ui_tx, background_rx, mqtt_tx, background_tx_clone)
            .await
            .unwrap();
    });

    // Getting user info
    let mut codename = String::new();
    print!("Insert codename: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut codename)?;
    let codename = codename.trim().to_string(); // Trim here

    background_tx.send(Command::Refresh).await.unwrap();

    // App loop
    let mut state;
    let mut user_command = Command::Refresh;
    loop {
        // Clear terminal
        //print!("\x1B[2J\x1B[H");
        //io::stdout().flush().unwrap();

        let msg = ui_rx
            .recv()
            .await
            .unwrap_or(CommandOutput::Error(String::from(
                "Failed to get response from background",
            )));
        match msg {
            CommandOutput::State(s) => state = s,
            CommandOutput::Error(msg) => {
                println!("{}", msg);
                break;
            }
            other => {
                println!("Unexpected response message: {:?}", other);
                break;
            }
        }

        match user_command {
            Command::ReloadPublicKeys => {
                println!("Public keys reloaded");
                println!("==========");
            }
            Command::SendMessage(target, _) => {
                println!("Message sent to {}", target);
                println!("==========");
            }
            Command::Refresh => {}
            Command::Quit => break,
            _ => {} // Use _ for other cases to avoid exhausting match
        }

        println!("Available commands:");
        println!("sm: send message");
        println!("rr: request revoke");
        println!("pi: publish identity");
        println!("rk: reload keys");
        println!("r: refresh");
        println!("q: quit");
        print!("Insert command: ");
        let mut user_input = String::new();
        io::stdout().flush()?;
        io::stdin().read_line(&mut user_input)?;

        let user_input = user_input.trim_end(); // Use trim_end for single newline
        user_command = string_to_command(user_input, &codename)?;

        background_tx.send(user_command.clone()).await.unwrap();
    }

    // Await both spawned tasks
    background_handle.await.unwrap();
    mqtt_handle.await.unwrap(); // Ensure MQTT handler also completes cleanly
    println!("bye bye ;)");
    Ok(())
}

// Update background function signature
async fn background(
    command_output: Sender<CommandOutput>,
    mut command: Receiver<Command>,
    mqtt_tx: Sender<MqttCommand>, // NEW: Pass the MQTT command sender
    background_tx_clone: Sender<Command>, // Keep this if needed for RevokeKey
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = Vec::new();

    // Key loading (unchanged)
    let mut ecdsa_key_pair = match ecdsa::load_keypair(ECDSA_SKEY_FILE, ECDSA_PKEY_FILE, &mut buf) {
        Ok(kp) => kp,
        Err(_) => {
            let kp = ecdsa::generate_keypair();
            ecdsa::export_keypair_to_file(&kp, ECDSA_SKEY_FILE, ECDSA_PKEY_FILE).unwrap();
            kp
        }
    };

    let mut rsa_key_pair = match rsa::load_keypair(RSA_SKEY_FILE, RSA_PKEY_FILE, &mut buf) {
        Ok(kp) => kp,
        Err(_) => {
            let kp = rsa::generate_keypair(RSA_SIZE).unwrap();
            rsa::export_keypair_to_file(&kp, RSA_SKEY_FILE, RSA_PKEY_FILE).unwrap();
            kp
        }
    };

    let mut target_rsa_pub_keys: HashMap<String, RsaPublicKey> = HashMap::new();
    let mut target_ecdsa_pub_keys: HashMap<String, VerifyingKey> = HashMap::new();
    let mut revoked: HashMap<String, bool> = HashMap::new();
    setup_pkeys_and_revokes(
        &mut target_rsa_pub_keys,
        &mut target_ecdsa_pub_keys,
        &mut revoked,
    )
    .expect("Failed to setup pkeys and revokes");

    let mut state = State::new(rsa_key_pair, ecdsa_key_pair);

    while let Some(msg) = command.recv().await {
        match msg {
            Command::MqttAddPublicKey(data) => {
                mqtt_add_public_keys(
                    data,
                    &mut revoked,
                    &target_rsa_pub_keys,
                    &mut target_ecdsa_pub_keys,
                );
            }
            Command::ReloadPublicKeys => {
                setup_pkeys_and_revokes(
                    &mut target_rsa_pub_keys,
                    &mut target_ecdsa_pub_keys,
                    &mut revoked,
                )
                .expect("Failed to setup pkeys and revokes");
            }
            Command::RevokeKey(payload) => {
                if should_revoke_key(&payload, &mut target_ecdsa_pub_keys) {
                    revoked.insert(payload.revogacao.unidade_revogada.clone(), true);
                    let json = serde_json::to_string(&revoked).unwrap();

                    let mut file = File::create("revoked.keys")
                        .expect("Failed to create file for revoked.keys: {}");

                    file.write_all(json.as_bytes()).unwrap();

                    setup_pkeys_and_revokes(
                        &mut target_rsa_pub_keys,
                        &mut target_ecdsa_pub_keys,
                        &mut revoked,
                    )
                    .unwrap();
                }
            }
            Command::RequestRevoke(target, codename) => {
                match request_revoke(&target, &codename, &mut state, &mqtt_tx) // Pass mqtt_tx
                    .await
                {
                    Ok(_) => {}
                    Err(err) => println!("{:?}", err),
                }
            }
            Command::SendMessage(target, content) => {
                match send_message(target, content, &target_rsa_pub_keys, &mut state, &mqtt_tx) // Pass mqtt_tx
                    .await
                {
                    Ok(_) => {}
                    Err(err) => println!("{:?}", err),
                }
            }
            Command::PublishIdentity(codename) => {
                match publish_identity(codename, &mut state, &mqtt_tx) // Pass mqtt_tx
                    .await
                {
                    Ok(_) => {}
                    Err(err) => println!("{:?}", err),
                }
            }
            Command::Quit => {
                command_output
                    .send(CommandOutput::State(state.clone()))
                    .await
                    .unwrap();
                break;
            }
            Command::Refresh => {}
        }

        command_output
            .send(CommandOutput::State(state.clone()))
            .await
            .unwrap();
    }
    Ok(())
}

fn mqtt_add_public_keys(
    data: PublicIdentityMessage,
    revoked: &mut HashMap<String, bool>,
    target_rsa_pub_keys: &HashMap<String, RsaPublicKey>,
    target_ecdsa_pub_keys: &mut HashMap<String, VerifyingKey>,
) {
    println!("{:?}", &data);
    if !revoked.contains_key(&data.id_unidade)
        && !target_rsa_pub_keys.contains_key(&data.id_unidade)
        && !target_ecdsa_pub_keys.contains_key(&data.id_unidade)
    {
        let mut file_rsa =
            File::create(format!("{}/{}", RSA_TARGETS_PKEY_FOLDER, &data.id_unidade)).expect(
                &format!(
                    "Failed to create file for rsa public key: {}",
                    &data.id_unidade
                )
                .to_string(),
            );
        let mut file_ecdsa = File::create(format!(
            "{}/{}",
            ECDSA_TARGETS_PKEY_FOLDER, &data.id_unidade
        ))
        .expect(
            &format!(
                "Failed to create file for ecdsa public key: {}",
                &data.id_unidade
            )
            .to_string(),
        );

        file_rsa
            .write_all(data.chave_publica_rsa.as_bytes())
            .expect("Failed to write rsa public key file");
        file_ecdsa
            .write_all(data.chave_publica_eddsa.as_bytes())
            .expect("Failed to write ecdsa public key file");
    }
}

fn setup_pkeys_and_revokes(
    target_rsa_pub_keys: &mut HashMap<String, RsaPublicKey>,
    target_ecdsa_pub_keys: &mut HashMap<String, VerifyingKey>,
    revoked: &mut HashMap<String, bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf: Vec<u8> = Vec::new();
    *target_rsa_pub_keys = HashMap::new();
    for entry in fs::read_dir(RSA_TARGETS_PKEY_FOLDER)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let mut f = fs::File::open(&path)?;
        f.read_to_end(&mut buf)?;
        let filename = path.file_name().unwrap().to_str().unwrap();
        let pkey = rsa::pkey_from_base64(&mut buf).unwrap();
        target_rsa_pub_keys.insert(filename.to_string(), pkey);
    }

    buf = Vec::new();
    *target_ecdsa_pub_keys = HashMap::new();
    for entry in fs::read_dir(ECDSA_TARGETS_PKEY_FOLDER)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let mut f = fs::File::open(&path)?;
        f.read_to_end(&mut buf)?;
        let filename = path.file_name().unwrap().to_str().unwrap();
        let pkey = ecdsa::pkey_from_base64(&mut buf).unwrap();
        target_ecdsa_pub_keys.insert(filename.to_string(), pkey);
    }

    *revoked = HashMap::new();
    {
        let mut revoked_file: fs::File;
        match fs::File::open("revoked.keys") {
            Ok(f) => revoked_file = f,
            Err(err) => panic!("Failed to open revoked.keys: {}", err),
        }

        let mut output = Vec::new();
        revoked_file
            .read_to_end(&mut output)
            .expect("Failed to read revoked.keys");

        let revoked_list: RevokedKeys =
            serde_json::from_slice(&output).expect("Failed to parse revoked.keys");
        for k in revoked_list.revoked {
            revoked.insert(k, true);
        }
    }

    Ok(())
}

// Update `publish_identity` to take Sender<MqttCommand>
async fn publish_identity(
    codename: String,
    state: &mut State,
    mqtt_tx: &Sender<MqttCommand>, // Changed type
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = PublicIdentityMessage {
        id_unidade: codename.clone(),
        chave_publica_rsa: rsa::encode_pkey_to_export(&state.rsa_key_pair.pkey).unwrap(),
        chave_publica_eddsa: ecdsa::encode_pkey_to_export(&state.ecdsa_key_pair.pkey).unwrap(),
    };
    let json = serde_json::to_string(&msg).expect("Failed to parse publish identity to json");
    let topic = format!("{}/{}", TOPIC_BROADCAST_KEYS, codename);

    mqtt_tx
        .send(MqttCommand::Publish {
            // Send command to MQTT handler
            topic,
            payload: json,
            qos: QoS::ExactlyOnce,
            retain: true,
        })
        .await?;

    Ok(())
}

// Update `send_message` to take Sender<MqttCommand>
async fn send_message(
    target: String,
    content: String,
    target_rsa_pub_keys: &HashMap<String, RsaPublicKey>,
    state: &mut State,
    mqtt_tx: &Sender<MqttCommand>, // Changed type
) -> Result<(), Box<dyn std::error::Error>> {
    let target_rsa_pkey;
    if let Some(rsa_pkey) = target_rsa_pub_keys.get(&target) {
        target_rsa_pkey = rsa_pkey;
    } else {
        return Err("Target RSA public key not found".into()); // Handle this gracefully
    }

    let mut hasher = Sha256::new();
    hasher.update(&content);
    let result = hasher.finalize();

    let assinatura: Signature = state.ecdsa_key_pair.skey.sign(&result);
    let assinatura_b64 = general_purpose::STANDARD.encode(assinatura.to_vec());

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let (ciphertext_b64, tag_autenticacao_b64, nonce_b64) =
        encrypt_aes256_gcm(&key, content.as_bytes()).unwrap();

    let chave_sessao_cifrada =
        target_rsa_pkey.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &key.to_vec())?;
    let chave_sessao_cifrada_b64 = general_purpose::STANDARD.encode(chave_sessao_cifrada.to_vec());

    let json = format!(
        "{{\"remetente\":\"{}\",\"ciphertext_b64\":\"{}\",\"tag_autenticacao_b64\":\"{}\",\"nonce_b64\":\"{}\",\"chave_sessao_cifrada_b64\":\"{}\",\"assinatura_b64\":\"{}\"}}",
        target,
        ciphertext_b64,
        tag_autenticacao_b64,
        nonce_b64,
        chave_sessao_cifrada_b64,
        assinatura_b64,
    );

    mqtt_tx
        .send(MqttCommand::Publish {
            // Send command to MQTT handler
            topic: format!("{}/{}", TOPIC_DM, target),
            payload: json,
            qos: QoS::ExactlyOnce,
            retain: false, // Assuming DM is not retained
        })
        .await?;

    Ok(())
}

fn should_revoke_key(
    payload: &RevokeMessage,
    target_ecdsa_pub_keys: &mut HashMap<String, VerifyingKey>,
) -> bool {
    if let Some(key) = target_ecdsa_pub_keys.get(&payload.remetente) {
        let json_str = serde_json::to_string(&payload.revogacao).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&json_str);
        let result = hasher.finalize();

        let s: Signature = Signature::from_slice(&payload.assinatura_b64.as_bytes()).unwrap();

        match key.verify(&result, &s) {
            Ok(_) => true,
            Err(_) => false,
        }
    } else {
        println!("NO KEY AVAILABLE FOR ECDSA ON REVOKE KEY");
        false
    }
}

// Update `request_revoke` to take Sender<MqttCommand>
async fn request_revoke(
    target: &String,
    codename: &String,
    state: &mut State,
    mqtt_tx: &Sender<MqttCommand>, // Changed type
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Local::now();
    let iso_8601_string = now.to_rfc3339();
    let content = RevokeContent {
        unidade_revogada: target.clone(),
        timestamp: iso_8601_string,
    };
    let json_msg = serde_json::to_string(&content).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&json_msg);
    let result = hasher.finalize();
    let signed: Signature = state.ecdsa_key_pair.skey.sign(&result.to_vec());

    let msg = RevokeMessage {
        remetente: codename.clone(),
        revogacao: content,
        assinatura_b64: signed.to_string(),
    };
    let json_msg = serde_json::to_string(&msg).unwrap();

    mqtt_tx
        .send(MqttCommand::Publish {
            // Send command to MQTT handler
            topic: TOPIC_REVOKE.to_string(),
            payload: json_msg,
            qos: QoS::ExactlyOnce,
            retain: true, // Assuming revoke messages are retained
        })
        .await?;

    Ok(())
}

fn encrypt_aes256_gcm(
    key: &Key<Aes256Gcm>,
    plaintext: &[u8],
) -> Result<(String, String, String), String> {
    let mut cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut ciphertext = Vec::new();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, plaintext, &mut ciphertext)
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let base64_ciphertext = general_purpose::STANDARD.encode(&ciphertext);
    let base64_tag = general_purpose::STANDARD.encode(&tag.to_vec());
    let base64_nonce = general_purpose::STANDARD.encode(&nonce.to_vec());

    Ok((base64_ciphertext, base64_tag, base64_nonce))
}

fn string_to_command(s: &str, codename: &String) -> Result<Command, String> {
    // ... (unchanged) ...
    if s == "q" {
        return Ok(Command::Quit);
    } else if s == "r" {
        return Ok(Command::Refresh);
    } else if s == "rr" {
        let mut target = String::new();
        print!("Target: ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut target).unwrap();
        // Trim target here as well!
        let target = target.trim().to_string();
        return Ok(Command::RequestRevoke(target, codename.to_string()));
    } else if s == "sm" {
        let mut target = String::new();
        print!("Target: ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut target).unwrap();
        // Trim target here as well!
        let target = target.trim().to_string();
        let mut msg = String::new();
        print!("Message: ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut msg).unwrap();
        // Trim msg here as well!
        let msg = msg.trim().to_string();

        return Ok(Command::SendMessage(target, msg));
    } else if s == "rk" {
        return Ok(Command::ReloadPublicKeys);
    } else if s == "pi" {
        return Ok(Command::PublishIdentity(codename.clone()));
    } else {
        return Err(String::from("Invalid command"));
    }
}
