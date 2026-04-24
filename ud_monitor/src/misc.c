//Test function to create inner maps, batch operations does not seem to be supported by this Kernel:(
void test_inner_batch(int* outer_fd)
{
	int ret = 0;
	int inner_fd[1000];
	unsigned int i_a[1000];
	unsigned int count = 1000;

	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
        .elem_flags = BPF_ANY
	);
	//printf("Started inner map creation\n");
	for(unsigned int i = 0;i<MAX_USERS;i++){
		for(unsigned int j = 0;j<1000;j++){
		i_a[j] = i;
		i++;
		inner_fd[j] = bpf_map_create(
		BPF_MAP_TYPE_HASH, // type
		"inner_map_struct", // name
		sizeof(struct service_meta), // key_size
		sizeof(struct service_info), // value_size
		MAX_SERVICES, // max_entries
		0); // flags

		if (inner_fd[j] < 0) {
			printf("FAIL: inner map create returned %d!\n", inner_fd[j]);
			return;
		}
		}
		ret = bpf_map_update_batch(*outer_fd, i_a, inner_fd, &count, &opts);
		if (ret < 0) { printf("outer map update_elem error: %d\n", ret); return; }
		//printf("Tick\n");


		for(unsigned int j = 0;j<1000;j++){
		close(inner_fd[j]);
		}
	}
	//printf("Ended inner map creation\n");
  	
	return;
}

void Test_precreation(int* outer_fd){
	unsigned int ind = 33;
	unsigned int* inner_map_id = malloc(sizeof(unsigned int));
	struct service_meta *key, *next_key;

	int ret = 0;
	ret = bpf_map_lookup_elem(*outer_fd, &ind, inner_map_id);
	if (ret < 0){
		printf("outer value not found\n");
		return;
	}

	unsigned int inner_fd = bpf_map_get_fd_by_id(*inner_map_id);
	if (inner_fd == 0) { printf("INVALID FD\n"); }

	struct in6_addr test_addr;
	test_addr.__in6_u.__u6_addr16[8] = 1;
	struct service_meta meta = {test_addr,1,1};
	struct service_meta next_meta = {0};
	struct service_info info = {0};
	struct service_info info1 = {0};
	struct service_info* info_p1 = &info1;
	next_key = &meta;
	key = &next_meta;
	info.tx_bytes = 666;
	ret = bpf_map_update_elem(inner_fd, &meta, &info, BPF_ANY);
	if (ret < 0){
		printf("Update problem: %d\n", ret);
		return;
	}
	bpf_map_get_next_key(inner_fd, &key, &next_key);
	if (next_key == NULL) {
		printf("next key null\n");
		return;
	}
	ret = bpf_map_lookup_elem(inner_fd, &next_key, info_p1);
	if (ret < 0){
		printf("inner value not found: %d\n", ret);
		return;
	}
	printf("Test success if 666 = %llu\n", info_p1->tx_bytes);
	return;
}

void *main_stater(void *arg) {
    
	int err;
	struct dispatcher_arg *args = (struct dispatcher_arg*)arg;
	struct service_meta service_key = {0}, service_nextkey = {0};
	struct service_info service_value;
	unsigned int outer_value; // inner map id
	unsigned int inner_fd; // inner map fd
	char addr_str[INET6_ADDRSTRLEN];
	char user_record[USER_REC_MAX_BYTE];
	char temp[100];
	char *lb = "\n";
	user_record[0] = '\0';
	inet_ntop(AF_INET6, &args->uIP.data, addr_str, sizeof(addr_str));
	if (strlen(user_record) + strlen(addr_str) < USER_REC_MAX_BYTE) {strcat(user_record, addr_str);} else {printf("Buffer overflow\n");}
	strcat(user_record, lb);

	err = bpf_map_lookup_elem(args->outer_fd, &args->inner_map_id, &outer_value);
	if (err < 0) { printf("Entry in outer map NOT found\n");return NULL; }

	inner_fd = bpf_map_get_fd_by_id(outer_value);
	if (inner_fd == 0) { printf("\tINVALID FD\n");return NULL; }

	for(unsigned int i;i<MAX_SERVICES;i++)
	{
		err = bpf_map_get_next_key(inner_fd, &service_key, &service_nextkey);
		if (err < 0) {break;}

		err = bpf_map_lookup_elem(inner_fd, &service_nextkey, &service_value);
		if (err < 0){printf("\tInner entry NOT found, err: %d\n", err); break;}
		inet_ntop(AF_INET6, &service_nextkey.service_addr, addr_str, sizeof(addr_str));
		if (strlen(user_record) + strlen(addr_str) < USER_REC_MAX_BYTE) {strcat(user_record, addr_str);} else {printf("Buffer overflow\n");}
		snprintf(temp, 100, "\t Port: %u, Protocol: %u, Rx bytes: %llu\n", service_nextkey.service_port, service_nextkey.protocol, service_value.rx_bytes);
		if (strlen(user_record) + strlen(temp) < USER_REC_MAX_BYTE) {strcat(user_record, temp);} else {printf("Buffer overflow\n");}
		service_key = service_nextkey;
	}
	if(fdp == 0){printf("File problem\n");close(inner_fd);return NULL;}
	size_t len = strlen(user_record);
	for(unsigned int i; i < 1000000;i++){
		if(pthread_mutex_trylock(&file_mutex) == 0) // Lock the mutex before accessing the file
		{
			fwrite(user_record, sizeof(char), len, fdp);
			pthread_mutex_unlock(&file_mutex); // Unlock the mutex before returning
			break;
		} 
		else{usleep(1);}
	}
	close(inner_fd);  
    return NULL;
}