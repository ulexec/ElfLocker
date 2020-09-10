#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <elf.h>
#include <ctype.h>
#include "../include/huffman.h"

static unsigned int qtail = -1;

int decode_bin(Node *root, Node *original, char *bytes, int len, uint8_t * decoded) {
	int nbyte = 0, n = 0, nbit = 7;
	char byte = bytes[0];	
	
	while( nbyte < len ) {
		while (nbit >= 0) {
			if(root->leaf){
				*(decoded + n++) = root->key;
				root = original;
			}
	  		root = (byte & (0x1 << nbit--)) ? root->right : root->left;		
		}
		nbit = 7;
		byte = bytes[++nbyte];
	}
	return n;

}

void qinsert(Node **nodes, Node *node){
	int i = 0, j = 0;

	if(qtail == -1) {
		nodes[++qtail] = node;
		return;
	}else{
		j = qtail+1;	
		for(i = qtail; i >= 0; i--){
		       if(node->freq <= nodes[i]->freq) {
				nodes[j--] = nodes[i];
				nodes[i] = node;
			}else{
				nodes[j] = node;
			    	break;
			}
		
		}
		qtail += 1;
		return;	
	}
}

void insert_node(Node **nodes, Node *left, Node *right, int freq, int key) {
	Node *node = (Node*) malloc(sizeof(Node));

	if(!freq && !key) {
		node->freq = left->freq + right->freq;
		node->key = 0;
		node->leaf = false;
		node->left = left;
		node->right = right;	
	}else{
		node->freq = freq;
		node->key = key;
		node->leaf = true;
		node->left = NULL;
		node->right = NULL;
	}
	qinsert(nodes, node);
}

void qdelete(Node **nodes, int idx) {
	int i;
	
	for (i = idx; i < qtail; i++) {
		nodes[i] = nodes[i+1];
	}
	qtail--;
}

int get_map_len(int *freqs) {
	int i, num = 0; 
	
	for(i = 0; i < QSIZE; i++) 
		if(freqs[i] != 0) num++;
	return num;
}

void init_hash_map(int sect_sz, int sect_off, int *freqs,  uint8_t *elf) {
	int i;

	for( i = 0; i < sect_sz; i++) {	
		if(elf[sect_off+i] == 0){
			freqs[0]+=1;
		}else{
			freqs[elf[sect_off+i]&0xff]+=1;
		}
	}
}

void insert_leaf_nodes(int *freqs, Node **nodes) {
	int i = 0;

	while(i < QSIZE) {
		if (freqs[i] != 0) {
			insert_node(nodes, NULL, NULL, freqs[i], i);
		}
		i++;
	}
}

Node *create_btree(int *freqs, Node **nodes) {
	qtail = -1;
	insert_leaf_nodes(freqs, nodes);

	while(qtail > 0){
		Node *left = *nodes;
		Node *right = *(nodes + 1);
		
		qdelete(nodes, 0);	
		insert_node(nodes, left, right, 0, 0);
		qdelete(nodes, 0);
	}
	return nodes[0];
}


