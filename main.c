#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <wchar.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define INIT_SIZE 8

typedef struct {
    uint8_t version;
    uint8_t pad;
    uint16_t length;
    uint32_t present;
    // uint8_t flags;
    // uint8_t rate;
    // uint16_t channel_freq;
    // uint16_t channel_flags;
    // uint8_t antenna_signal;
    // uint8_t antenna;
    // uint8_t rx_flags;
} radiotap;

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t frag_seq;
} frame;

typedef struct {
  uint64_t timestamp;
  uint16_t interval;
  uint16_t capabilities;
} fixed;

typedef struct {
  uint8_t id;
  uint8_t length;
} tag;

typedef struct {
  tag t;
  wchar_t *ssid;
} ssid;

typedef struct {
  tag t;
  uint8_t supported_rates[8];
} suported_rates;

typedef struct {
  tag t;
  uint8_t current;
} channel;

typedef struct {
  radiotap r;
  frame fr;
  fixed fi;
  ssid s;
  suported_rates sr;
  channel c;
} _80211;

typedef struct {
  char *interface;
  wchar_t *ssid;
  int crypt;
} args;

char* str(int size) {
	char* string = (char*)malloc(sizeof(char) * size);

	for (int i = 0; i < size; i++)
		string[i] = '\0';

	return string;
}

char** split(char *sentence, char separator) {
	char** tokens;
	int* lengths;
	int tokens_idx = 0;
	int token_idx = 0;
	int num_tokens = 1;

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator)
			(num_tokens)++;
	}

	lengths = (int*)malloc(sizeof(int) * (num_tokens));
	tokens = (char**)malloc(sizeof(char*) * (num_tokens));

	for (int i = 0; i < num_tokens; i++) {
		tokens[i] = str(INIT_SIZE);
		lengths[i] = INIT_SIZE;
	}

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator && strlen(tokens[tokens_idx]) != 0) {
			token_idx = 0;
			tokens_idx++;
		}
		else if (sentence[i] == separator && strlen(tokens[tokens_idx]) == 0){
			continue;
		}
		else {
			/* Memory reallocation, If  array is full. */

			if (strlen(tokens[tokens_idx]) == lengths[tokens_idx] - 1) {
				tokens[tokens_idx] = realloc(tokens[tokens_idx], (lengths[tokens_idx] * sizeof(char)) << 1);

				for (int j = lengths[tokens_idx]; j < lengths[tokens_idx] << 1; j++)
					tokens[tokens_idx][j] = '\0';

				lengths[tokens_idx] <<= 1;
			}

			tokens[tokens_idx][token_idx] = sentence[i];
			token_idx++;
		}
	}

	return tokens;
}


void usage() {
	printf("syntax : beacon <interface> <file>\n");
	printf("sample : beacon wlan0 ssid.txt\n");
}

void sendBeacon(args* argv) {
  pcap_t* handle = pcap_open_live(argv->interface, BUFSIZ, 1, 1000, NULL);
  if (handle == NULL) {
      printf("failed to open %s\n", argv->interface);
      return;
  }
  _80211* beacon = (_80211*)malloc(sizeof(_80211));
  beacon->r.version = 0;
  beacon->r.pad = 0;
  beacon->r.length = 8;
  // beacon->r.length = 18;
  beacon->r.present = 0x00000000;
  // beacon->r.present = 0x0000482e;
  // beacon->r.flags = 0x10;
  // beacon->r.rate = 0x82;
  // beacon->r.channel_freq = 0x096c;
  // beacon->r.channel_flags = 0x00a0;
  // beacon->r.antenna_signal = 0xbc;
  // beacon->r.antenna = 0x00;
  // beacon->r.rx_flags = 0x0000;
  beacon->fr.type = 0x80;
  beacon->fr.flags = 0x00;
  beacon->fr.duration = 0x0000;
  for(int i = 0; i < 6; i++) beacon->fr.dest[i] = 0xff;
  int randomData = open("/dev/urandom", O_RDONLY);
  srand(randomData);
  for(int i = 0; i < 6; i++) {
    int r = rand() % 256;
    beacon->fr.src[i] = r;
    beacon->fr.bssid[i] = r;
  }
  printf("\n");
  beacon->fr.frag_seq = 0x0000;
  beacon->fi.timestamp = 0x00000000000000;
  beacon->fi.interval = 0x0000;
  beacon->fi.capabilities = 0x0001;
  if (argv->crypt == 1) beacon->fi.capabilities |= 0x0010;
  beacon->s.t.id = 0x00;
  beacon->s.t.length = strlen(argv->ssid);
  beacon->s.ssid = (uint8_t*)malloc(sizeof(uint8_t) * strlen(argv->ssid));
  memcpy(beacon->s.ssid, argv->ssid, strlen(argv->ssid));
  beacon->sr.t.id = 0x01;
  beacon->sr.t.length = 8;
  beacon->sr.supported_rates[0] = 0x82;
  beacon->sr.supported_rates[1] = 0x84;
  beacon->sr.supported_rates[2] = 0x8b;
  beacon->sr.supported_rates[3] = 0x96;
  beacon->sr.supported_rates[4] = 0x0c;
  beacon->sr.supported_rates[5] = 0x12;
  beacon->sr.supported_rates[6] = 0x18;
  beacon->sr.supported_rates[7] = 0x24;
  beacon->c.t.id = 0x03;
  beacon->c.t.length = 1;
  beacon->c.current = 0x01;

  int size = beacon->r.length + 24 + 12 + 2 + strlen(argv->ssid) + beacon->sr.t.length + 2 + (beacon->c.t.length + 2);
  int ssid_padding = beacon->r.length + 24 + 12 + 2;
  uint8_t* packet = (uint8_t*)malloc(sizeof(uint8_t) * size);
  memcpy(packet, &beacon->r, beacon->r.length);
  memcpy(packet + beacon->r.length, &beacon->fr, 24);
  memcpy(packet + beacon->r.length + 24, &beacon->fi, 12);
  memcpy(packet + beacon->r.length + 24 + 12, &beacon->s.t, 2);
  memcpy(packet + ssid_padding, beacon->s.ssid, strlen(argv->ssid));
  memcpy(packet + ssid_padding + strlen(argv->ssid), &beacon->sr, beacon->sr.t.length + 2);
  memcpy(packet + ssid_padding + strlen(argv->ssid) + beacon->sr.t.length + 2, &beacon->c, sizeof(channel));
  free(beacon->s.ssid);
  free(beacon);
  // 구조체 왜 썼지..
  while(1) {
    pcap_sendpacket(handle, packet, size);
  }
  pcap_close(handle);
}

int main(int argc, wchar_t* argv[]) {
  if (argc < 2) {
		usage();
		return -1;
	}
  FILE* f = fopen(argv[2], "r");
  if(f == NULL) {
      printf("failed to open %s\n", argv[2]);
      return -1;
  }

  int length = 0;
  wchar_t c;
  while((c = fgetc(f)) != EOF) {
    if(c == '\n') length++;
  }

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  wchar_t* ssidraw = malloc(fsize + 1);
  fread(ssidraw, fsize, 1, f);
  fclose(f);

  wchar_t** ssid_list = split(ssidraw, '\n');
  free(ssidraw);

  args *argvs[length];
  for(int i = 0; i < length; i++) {
    argvs[i] = (args*)malloc(sizeof(args));
    argvs[i]->ssid = ssid_list[i];
    argvs[i]->interface = argv[1];
    if (argc == 4 && !strcmp(argv[3], "--crypt")) argvs[i]->crypt = 1;
    else argvs[i]->crypt = 0;
  }


  pthread_t p_thread[length];
  for(int i = 0; i < length; i++) {
    pthread_create(&p_thread[i], NULL, sendBeacon, argvs[i]);
    pthread_detach(p_thread[i]);
  }
  while(1) sleep(1);
  free(ssid_list);
  return 0;
}
