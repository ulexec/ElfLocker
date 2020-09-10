void get_num_of_chunks(int text_size, int *nchunks, int *align);
void encrypt_decrypt_block(char *chunk, int chunk_size, char *key, void (*f)(char*, char*, int));
void get_next_key(char *data, int size, char *key);
int get_function_for_encrypting(char* crc);
void encrypt_data(int total_size, char *plain_data);
void decrypt_data(int nchunks, int align, char *encrypted_data);
int encrypt_buff(char *data, int size);
void decrypt_buff(char *data, int size);