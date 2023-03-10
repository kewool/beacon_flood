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
    uint8_t flags;
    uint8_t rate;
    uint16_t channel_freq;
    uint16_t channel_flags;
    uint8_t antenna_signal;
    uint8_t antenna;
    uint8_t rx_flags;
} radiotap;

void setRadiotap(radiotap* r, int channel) {
    r->version = 0;
    r->pad = 0;
    r->length = 18;
    r->present = 0x0000482e;
    r->flags = 0x00;
    r->rate = 0x82;
    r->channel_freq = 2412 + ((channel - 1) * 5);
    if (channel == 14) r->channel_freq = 2484;
    r->channel_flags = 0x00a0;
    r->antenna_signal = 0xff;
    r->antenna = 0x00;
    r->rx_flags = 0x0000;
}

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t frag_seq;
} frame;

void setFrame(frame* fr) {
  fr->type = 0x80;
  fr->flags = 0x00;
  fr->duration = 0x0000;
  for(int i = 0; i < 6; i++) fr->dest[i] = 0xff;
  int randomData = open("/dev/urandom", O_RDONLY);
  srand(randomData);
  for(int i = 0; i < 6; i++) {
    int r = rand() % 256;
    fr->src[i] = r;
    fr->bssid[i] = r;
  }
  fr->frag_seq = 0x0000;
}

typedef struct {
  uint64_t timestamp;
  uint16_t interval;
  uint16_t capabilities;
} fixed;

void setFixed(fixed* fi, int crypt) {
  fi->timestamp = 0x00000a00ab7e8183;
  fi->interval = 0x0064;
  fi->capabilities = 0x0401;
  if (crypt == 1) fi->capabilities |= 0x0010;
}

typedef struct {
  uint8_t id;
  uint8_t length;
} tag;

typedef struct {
  tag t;
  wchar_t *ssid;
} ssid;

void setSSID(ssid* s, wchar_t *ssid) {
  s->t.id = 0x00;
  s->t.length = strlen(ssid);
  s->ssid = ssid;
}

typedef struct {
  tag t;
  uint8_t supported_rates[8];
} suported_rates;

void setSupportedRates(suported_rates* sr) {
  sr->t.id = 0x01;
  sr->t.length = 8;
  sr->supported_rates[0] = 0x82;
  sr->supported_rates[1] = 0x84;
  sr->supported_rates[2] = 0x8b;
  sr->supported_rates[3] = 0x96;
  sr->supported_rates[4] = 0x0c;
  sr->supported_rates[5] = 0x12;
  sr->supported_rates[6] = 0x18;
  sr->supported_rates[7] = 0x24;
}

typedef struct {
  tag t;
  uint8_t current;
} channel;

void setChannel(channel* c, uint8_t channel) {
  c->t.id = 0x03;
  c->t.length = 1;
  c->current = channel;
}

typedef struct {
  tag t;
  uint16_t rsn_version;
  uint16_t group_cipher_suite[2];
  uint16_t pairwise_cipher_suite_count;
  uint16_t pairwise_cipher_suite_list[4];
  uint16_t akm_suite_count;
  uint16_t akm_suite_list[4];
  uint16_t rsn_capabilities;
} rsn_info;

void setRSN(rsn_info* rsn) {
  rsn->t.id = 0x30;
  rsn->t.length = 24;
  rsn->rsn_version = 0x01;
  rsn->group_cipher_suite[0] = 0x0f00;
  rsn->group_cipher_suite[1] = 0x02ac;
  rsn->pairwise_cipher_suite_count = 0x0002;
  rsn->pairwise_cipher_suite_list[0] = 0x0f00;
  rsn->pairwise_cipher_suite_list[1] = 0x04ac;
  rsn->pairwise_cipher_suite_list[2] = 0x0f00;
  rsn->pairwise_cipher_suite_list[3] = 0x02ac;
  rsn->akm_suite_count = 0x0001;
  rsn->akm_suite_list[0] = 0x0f00;
  rsn->akm_suite_list[1] = 0x02ac;
  rsn->rsn_capabilities = 0x000c;
}

typedef struct {
  radiotap r;
  frame fr;
  fixed fi;
  ssid s;
  suported_rates sr;
  channel c;
  rsn_info rsn;
} _80211;

typedef struct {
  char *interface;
  wchar_t *ssid;
  uint8_t crypt;
  uint8_t channel;
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
	printf("syntax : beacon-flood <interface> <file> [optianl: -c, --crypt]\n");
	printf("sample : beacon-flood wlan0 ssid.txt -c 5 --crypt -\n");
}

void sendBeacon(args* argv) {
  pcap_t* handle = pcap_open_live(argv->interface, BUFSIZ, 1, 1000, NULL);
  if (handle == NULL) {
      printf("failed to open %s\n", argv->interface);
      return;
  }
  _80211* beacon = (_80211*)malloc(sizeof(_80211));
  setRadiotap(&beacon->r, argv->channel);
  setFrame(&beacon->fr);
  setFixed(&beacon->fi, argv->crypt);
  setSSID(&beacon->s, argv->ssid);
  setSupportedRates(&beacon->sr);
  setChannel(&beacon->c, argv->channel);
  if (argv->crypt == 1) setRSN(&beacon->rsn);

  int size = beacon->r.length + 24 + 12 + 2 + strlen(argv->ssid) + beacon->sr.t.length + 2 + (beacon->c.t.length + 2);
  if (argv->crypt == 1) size += beacon->rsn.t.length + 2;
  int ssid_padding = beacon->r.length + 24 + 12 + 2;
  uint8_t* packet = (uint8_t*)malloc(sizeof(uint8_t) * size);
  memcpy(packet, &beacon->r, beacon->r.length);
  memcpy(packet + beacon->r.length, &beacon->fr, 24);
  memcpy(packet + beacon->r.length + 24, &beacon->fi, 12);
  memcpy(packet + beacon->r.length + 24 + 12, &beacon->s.t, 2);
  memcpy(packet + ssid_padding, beacon->s.ssid, strlen(argv->ssid));
  memcpy(packet + ssid_padding + strlen(argv->ssid), &beacon->sr, beacon->sr.t.length + 2);
  memcpy(packet + ssid_padding + strlen(argv->ssid) + beacon->sr.t.length + 2, &beacon->c, sizeof(channel));
  if (argv->crypt == 1) memcpy(packet + ssid_padding + strlen(argv->ssid) + beacon->sr.t.length + 2 + sizeof(channel), &beacon->rsn, beacon->rsn.t.length + 2);
  free(beacon->s.ssid);
  free(beacon);
  // ????????? ??? ??????..
  while(1) {
    pcap_sendpacket(handle, packet, size);
  }
  pcap_close(handle);
}

int main(int argc, char* argv[]) {
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
  uint8_t crypt = 0;
  uint8_t channel = 1;
  if (argc > 3) {
    for (int j = 3; j < argc; j++) {
      printf("%s", argv[j]);
      if (!strcmp(argv[j], "--crypt")) crypt = 1;
      if (!strcmp(argv[j], "-c")) channel = atoi(argv[j+1]);
    }
  }

  char command[30];
  sprintf(command, "iwconfig %s channel %d", argv[1], channel);
  system(command);

  for(int i = 0; i < length; i++) {
    argvs[i] = (args*)malloc(sizeof(args));
    argvs[i]->ssid = ssid_list[i];
    argvs[i]->interface = argv[1];
    argvs[i]->crypt = crypt;
    argvs[i]->channel = channel;
  }


  pthread_t p_thread[length];
  for(int i = 0; i < length; i++) {
    pthread_create(&p_thread[i], NULL, sendBeacon, argvs[i]);
    pthread_detach(p_thread[i]);
  }
  while(1) sleep(100);
  free(ssid_list);
  return 0;
}
