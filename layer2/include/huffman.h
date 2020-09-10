
#define QSIZE 0xff + 1 

typedef struct __node_t {
	int freq;
	char key;
	bool leaf;
	struct __node_t *left, *right;
} Node;

int decode_bin(Node *root, Node *original, char *bytes, int len, uint8_t *decoded);
void qinsert(Node **nodes, Node *node);
void insert_node(Node **nodes, Node *left, Node *right, int freq, int key);
void qdelete(Node **nodes, int idx);
int get_map_len(int *freqs);
void encode(Node *root, int len, char *code, int nleaf_nodes);
void decode(Node *root, Node *original, char *bits, int len);
void insert_leaf_nodes(int *freqs, Node **nodes);
Node *create_btree(int *freqs, Node **nodes);




