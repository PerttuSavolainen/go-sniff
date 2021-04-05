#include <odroid_go.h>


#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_internal.h"
#include "lwip/err.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include <Arduino.h>
//#include <TimeLib.h>
#include "FS.h"
#include "SD.h"
#include "SPI.h"
//#include <PCAP.h>


#include <Preferences.h>
#include "WiFi.h"

#define CHANNEL 1
#define MAX_CHANNEL 11
#define CHANNEL_HOPPING true //if true it will scan on all channels
#define HOP_INTERVAL 214 //in ms (only necessary if channelHopping is true
#define SSIDLENPOS 25
#define SOURCEMACPOS 10

String ver = "v0.0.1";
bool scanOngoing = false;
Preferences preferences;

unsigned long lastTime = 0;
unsigned long lastChannelChange = 0;
int ch = CHANNEL;
bool snifferRunning = true;
byte lcdLineCount = 0;


void setup() {
  GO.begin();
  preferences.begin("packet-sniffer", false);
  
  setupTitle();
  // Serial.begin(115200);
  
  // scanNetworksSetup();




  sniffSetup();
}

void loop() {
  // scanWifiAPs();


  snifferLoop();
}

void setupTitle() {
  GO.lcd.clearDisplay();
  GO.lcd.setCursor(0, 0);
  GO.lcd.setTextSize(1.75);
  GO.lcd.println("Wifi tools " + ver);
  GO.lcd.println("Scan networks with A-Button");
}

void scanNetworksSetup() {
  // Set WiFi to station mode and disconnect from an AP if it was previously connected
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  Serial.println("Setup done");
}

void sniffSetup() {
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_AP) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  // monitor mode
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniffer);
  wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
  esp_wifi_set_channel(ch, secondCh);

  Serial.println("Sniffer started!");
  GO.lcd.println("Sniffer started!");
}

void scanWifiAPs() {
  GO.update();

  if (GO.BtnA.isPressed() == 1 && !scanOngoing) {
    scanOngoing = true;
    
    setupTitle();
    GO.lcd.println("");
    GO.lcd.println("Scan started!");

    Serial.println("Scan started!");

    // WiFi.scanNetworks will return the number of networks found
    int n = WiFi.scanNetworks();
    Serial.println("scan done");
    
    unsigned int counter = preferences.getUInt("counter", 0);
    counter++;
    Serial.print("Current counter value: ");
    Serial.println(counter);
    preferences.putUInt("counter", counter);
    
    if (n == 0) {
      Serial.println("no networks found");
    } else {
      Serial.print(n);
      Serial.println(" networks found");
      GO.lcd.print(n);
      GO.lcd.println(" networks found");
      for (int i = 0; i < n; ++i) {
        // show ssid, mac address and rssi
        //Serial.print(i + 1);
        Serial.print(WiFi.SSID(i));
        Serial.print(" (");
        Serial.print(WiFi.RSSI(i));
        Serial.print(")");
        Serial.println((WiFi.encryptionType(i) == WIFI_AUTH_OPEN)?" ":"*");
        GO.lcd.print(WiFi.SSID(i));
        GO.lcd.print(" (");
        GO.lcd.print(WiFi.RSSI(i));
        GO.lcd.print(")");
        GO.lcd.println((WiFi.encryptionType(i) == WIFI_AUTH_OPEN)?" ":"*");
        delay(10);
      }
    }
    GO.lcd.println("");
    Serial.println("");
    
  
    // Wait a bit before scanning again
    delay(5000);
    scanOngoing = false;
  }
}

void sniffProbeRequests() {

}






esp_err_t event_handler(void *ctx, system_event_t *event) {
  return ESP_OK;
}

void snifferLoop() {
  unsigned long currentTime = millis();
  GO.update();
  /* Channel Hopping */
  if (CHANNEL_HOPPING && snifferRunning) {
    if (currentTime - lastChannelChange >= HOP_INTERVAL) {
      lastChannelChange = currentTime;
      ch++; //increase channel
      if (ch > MAX_CHANNEL) ch = 1;
      wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
      esp_wifi_set_channel(ch, secondCh);
    }
  }
}


/* will be executed on every packet the ESP32 gets while being in promiscuous mode */
void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  //uint32_t timestamp = now(); //current timestamp
  //uint32_t microseconds = (unsigned int)(micros() - millis() * 1000); //micro seconds offset (0 - 999)
  //pcap.newPacketSD(timestamp, microseconds, ctrl.sig_len, pkt->payload); //write packet to file
  byte pktType = pkt->payload[0];

  Serial.println(pktType);
  
  if (pktType == 0x40) {
    if (lcdLineCount > 30) {
      GO.lcd.clearDisplay();
      GO.lcd.setCursor(0, 0);
      lcdLineCount = 0;
    }



    byte ssidLen = pkt->payload[SSIDLENPOS];
    if (ssidLen > 0) {
      Serial.print("Debug: ");
      for (byte i = 1; i < SSIDLENPOS; i++) {
        
        Serial.print(pkt->payload[i], HEX);
        Serial.print(", ");
      }
      byte sourceMac[6];
      Serial.print("Source MAC: ");
      for (byte i = 0; i < 6; i++) {
        sourceMac[i] = pkt->payload[SOURCEMACPOS + i];
        Serial.print(sourceMac[i], HEX);
        GO.lcd.print(sourceMac[i], HEX);
        if (i < 5) {
          Serial.print(":");
          GO.lcd.print(":");
        }
      }
      GO.lcd.print(" ");
      Serial.print(" ");

      char ssidName[64];
      for (byte i = 0; i < ssidLen; i++) {
        ssidName[i] = pkt->payload[SSIDLENPOS + 1 + i];
      }
      ssidName[ssidLen] = '\0';
      Serial.print(ssidName);
      GO.lcd.print(ssidName);

      GO.lcd.println("");
      Serial.println("");
      lcdLineCount++;
    }
  }
}




// sniff only probe requests

// toggle screen on/off from start
// toggle sniffing on/off from A

// scan wifi networks
// list also hidden networks (name is empty)

// -> evil twin?
