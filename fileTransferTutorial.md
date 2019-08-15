Tutorial: Making a simple file-transfer application. 
Code by Yinran Lei
-----
In this tutorial, you'll learn how to build a simple application that will transfer a file from one place to another using ndn-iot over unicast. Notably, this tutorial assumes that you've installed NFD, ndn-cxx, and ndn-iot-package-over posix (respective pointers: ). The security bootstrapping is dependent upon having the ndn-iot-controller installed as well. 
----
Installation notes: 
----
--
Definitions: Though I'd recommend using the NDN documentation (https://named-data.net/project/specifications/) for a full explanation of these terms, hopefully this will serve as a useful reference for quick lookups.

Face: An abstraction that handles layer 2 network communication (deals with interests, data, etc).

Interest: An interest is a request for a piece of data (by name).

Data: A piece of data is exactly what it sounds like, with the one caveat that it is named and immutable. 

[Anything else that's necessary]

-----

Tutorial: Making a simple file-transfer application. 
Code by Yiran Lei
-----
In this tutorial, you'll learn how to build a simple application that will transfer a file from one place to another using ndn-iot over unicast. 
--
Definitions: Though I'd recommend using the NDN documentation (https://named-data.net/project/specifications/) for a full explanation of these terms, hopefully this will serve as a useful reference for quick lookups.

Face: An abstraction that handles layer 2 network communication (deals with interests, data, etc).

Interest: An interest is a request for a piece of data (by name).

Data: A piece of data is exactly what it sounds like, with the one caveat that it is named and immutable. 

[Anything else that's necessary]

-----

Writing the server: 
As a broad overview, we'd like to write a server that, given a client IP, the local and client port numbers, and an NDN name prefix, will wait for a client interest for a file, then return that file. 
Let's walk through the program [link here] and investigate the interesting parts. 

The following statements illustrate how to initialize and set up our server. Fortunately, almost all of the heavy lifting is taken care of by the library. 

```
int main(int argc, char *argv[]){
  int ret;
  ndn_encoder_t encoder;

  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  ndn_lite_startup();
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, client_ip, port2);

  running = true;
  encoder_init(&encoder, buf, sizeof(buf));
  ndn_name_tlv_encode(&encoder, &name_prefix);
  ndn_forwarder_register_prefix(encoder.output_value, encoder.offset, on_interest, NULL);
  while(running){
    ndn_forwarder_process();
    usleep(10000);
  }

  ndn_face_destroy(&face->intf);

  return 0;
}

```

To begin with, we check our arguments to see if they make sense (e.g. the port number is between 1024 and 65536, the name is a valid NDN prefix, etc), and then start up ndn-lite, as well as construct the face (see glossary) that will deal with our communication primitives. 

```
  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  ndn_lite_startup();
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, client_ip, port2);

```

After that, we proceed with a bit more setup. We need to initialize our encoder (which does type-length-value/TLV encoding), along with actually registering the name on the network. 

```
  encoder_init(&encoder, buf, sizeof(buf));
  ndn_name_tlv_encode(&encoder, &name_prefix);
  ndn_forwarder_register_prefix(encoder.output_value, encoder.offset, on_interest, NULL);
```
After that, our initialization is done! We can simply progress the forwarder, waiting for an interest to come in. 
```
  while(running){
    ndn_forwarder_process();
    usleep(10000);
  }
```

However, we still haven't implemented the function `on_interest`, which gives the forwarder instruction on what do when it receives an interest (this is, of course, the most important part of the server, as well as where the real action of any application is going to take place).
To that end, we create a simple `on_interest` function that will respond to an interest with the data requested. 

```
int on_interest(const uint8_t* interest, uint32_t interest_size, void* userdata){
  ndn_data_t data;
  ndn_encoder_t encoder;

  printf("On interest\n");

  ndn_interest_t ek_interest;

  ndn_name_t ek_name;
  // char file_name[1024];
  char* file_name;
  int param_size;
  tlv_parse_interest(interest,interest_size,3,TLV_INTARG_NAME_PTR,&ek_name,TLV_INTARG_PARAMS_BUF,(uint8_t**)&file_name,TLV_INTARG_PARAMS_SIZE,&param_size);
  file_name[param_size] = '\0';

  char temp_buffer[1024];
  FILE *fp = fopen(file_name,"r");
  printf("The requested file name is: %s\n",file_name);
  if(fp == NULL){
    fprintf(stderr, "ERROR: fail to open file.\n");
    return 1;
  }
  if(fgets(temp_buffer,1024,fp) == NULL){
    fprintf(stderr, "ERROR: fail to read file.\n");
    return 2;
  }
  //printf("The content of the file is: %s, %lu\n",temp_buffer,strlen(temp_buffer) );

  uint8_t data_buf[4096];
  int data_off;
  tlv_make_data(data_buf,4096,&data_off,3,TLV_DATAARG_NAME_PTR,&ek_name,TLV_DATAARG_CONTENT_BUF,(uint8_t*)temp_buffer,TLV_DATAARG_CONTENT_SIZE,strlen(temp_buffer));
  ndn_forwarder_put_data(data_buf,data_off);
  return 0;
}
```

First, we use ``tlv_parse_interest`` to parse the interest (<span style="color:blue">Put a pointer (in this case, it is `file_name`) to the  to the `tlv_parse_interest` function to get the parameters of the interest. Since there is only one parameter in the interest, which is the requested file name, we then get the name of the requested file by `file_name`</span>). 

```
  ndn_name_t ek_name;
  // char file_name[1024];
  char* file_name;
  int param_size;
  tlv_parse_interest(interest,interest_size,3,TLV_INTARG_NAME_PTR,&ek_name,TLV_INTARG_PARAMS_BUF,(uint8_t**)&file_name,TLV_INTARG_PARAMS_SIZE,&param_size);
  file_name[param_size] = '\0';

  char temp_buffer[1024];
```
Next, we make a data packet out of the requested file using the `tlv_make_data` function. The function takes in a buffer as an argument (`data_buf`), which holds the relevant packet.   
```
FILE *fp = fopen(file_name,"r");
  printf("The requested file name is: %s\n",file_name);
  if(fp == NULL){
    fprintf(stderr, "ERROR: fail to open file.\n");
    return 1;
  }
  if(fgets(temp_buffer,1024,fp) == NULL){
    fprintf(stderr, "ERROR: fail to read file.\n");
    return 2;
  }
  //printf("The content of the file is: %s, %lu\n",temp_buffer,strlen(temp_buffer) );

  uint8_t data_buf[4096];
  int data_off;
  tlv_make_data(data_buf,4096,&data_off,3,TLV_DATAARG_NAME_PTR,&ek_name,TLV_DATAARG_CONTENT_BUF,(uint8_t*)temp_buffer,TLV_DATAARG_CONTENT_SIZE,strlen(temp_buffer));
```
Lastly, we use the forwarder to respond to the interest with the appropriate data (the requested file, held within `data_buf`). 
```
  ndn_forwarder_put_data(data_buf,data_off);

```

-----
Writing the client:
Now that we've written up the server, we can create a client that, when provided with a local port, server ip, server port, name and file name, can request said file from the server. As before, we'll stick to examining critical pieces of the code. 

We'll begin in the same way as above: by initializing and registering ourselves on the network. However, we'll also take the opportunity to express an interest.<span style="color:blue">When sending the interest, we assign the name of the wanted file as the only parameter of the interest, which will be later received by the server as shown above.</span>

```
int main(int argc, char *argv[]){
  ndn_udp_face_t *face;
  ndn_interest_t interest;
  ndn_encoder_t encoder;
  int ret;

  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  ndn_lite_startup();

  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, server_ip, port2);
  running = true;
  encoder_init(&encoder, buf, 4096);
  ndn_name_tlv_encode(&encoder, &name_prefix);
  ndn_forwarder_add_route(&face->intf, buf, encoder.offset);

  char interest_buf[4096];
  int interest_off;
  tlv_make_interest(interest_buf,4096,&interest_off,3,TLV_INTARG_NAME_PTR,&name_prefix,TLV_INTARG_PARAMS_BUF,(uint8_t*)file_name,TLV_INTARG_PARAMS_SIZE,strlen(file_name));
  ndn_forwarder_express_interest(interest_buf, interest_off, on_data, on_timeout, NULL);

  while(running){
    ndn_forwarder_process();
    usleep(10000);
  }

  ndn_face_destroy(&face->intf);

  return 0;
}
```
Just as in the server code we had to create the function `on_interest`, in the client we have to provide the function `on_data`, which will control what to do when the client receives the relevant data/file back. 

When the client receives data, it first parses the data using the `tlv_parse_data function`, and copies it into a buffer (``data_buf``), it then saves this buffer as a file. 

```
void on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata){
  ndn_data_t data;
  printf("Receiving data\n");
  // char data_buf[1024];
  char* data_buf;
  int data_off;
  tlv_parse_data(rawdata,data_size,2,TLV_DATAARG_CONTENT_BUF,(uint8_t**)&data_buf,TLV_DATAARG_CONTENT_SIZE,&data_off);
  //printf("data\n%s\n",data_buf);
  save_file(data_buf);
}
```

-------------

That covers a simple file transfer application. Now how might we go about including security? The full documentation can be found at https://github.com/named-data-iot/ndn-lite/wiki, but the general summary is this: the current implementation in ndn-lite involves using a controller (in this case a macbook) as the trust anchor. This controller distributes certificates to devices given a shared secret (e.g. a QR code). Devices can then use these certificates when communicating with one another for both identity verification and cryptography. 

However, in order to avoid overcomplicating this tutorial, we'll stick with a client/server model and simulate what the controller would be doing. As above, we'll set up our server first. However, we'll also go through and examine what must be done differently when including security. 

-----
We'll start our main method in the same we did before, by parsing the command-line arguments, starting up ndn-lite, and constructing our face.
```
int main(int argc, char *argv[]){
  int ret;
  ndn_encoder_t encoder;

  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  ndn_lite_startup();
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, client_ip, port2);
```
However, we then move into the bootstrapping process. Suppose that the controller's public and private keys are `secp256r1_pub_key_str` and `secp256r1_prv_key_str` respectively. We can turn these into `ndn_ecc` (ndn ellyptic curve cryptography) data structures and initialize them:
(Additional note: `NDN_ECDSA_CURVE_SECP256R1` here just specifies the type of ECC curve, where `123` represents the unique key id.) 
```
ndn_ecc_prv_t anchor_prv_key;
  ndn_ecc_prv_init(&anchor_prv_key, secp256r1_prv_key_str, sizeof(secp256r1_prv_key_str),
                   NDN_ECDSA_CURVE_SECP256R1, 123);
  ndn_ecc_pub_t anchor_pub_key;
  ndn_ecc_pub_init(&anchor_pub_key, secp256r1_pub_key_str, sizeof(secp256r1_pub_key_str), NDN_ECDSA_CURVE_SECP256R1, 123);
```
We continue to simulate the role of the controller, making a cryptographically signed data packet (from the controller) that contains the controller's public key as the packet's contents.  Notably, here, 123/456 are the unique key id of the anchor's key. Every key (should) have a unique id. 
```
  ndn_data_t anchor;
  ndn_data_init(&anchor);
  ndn_name_from_string(&anchor.name, "/ndn-iot/controller/KEY", strlen("/ndn-iot/controller/KEY"));
  ndn_name_t anchor_id;
  memcpy(&anchor_id, &anchor.name, sizeof(ndn_name_t));
  anchor_id.components_size -= 1;
  ndn_name_append_keyid(&anchor.name, 123);
  ndn_name_append_string_component(&anchor.name, "self", strlen("self"));
  ndn_name_append_keyid(&anchor.name, 456);
  ndn_data_set_content(&anchor, secp256r1_pub_key_str, sizeof(secp256r1_pub_key_str));
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &anchor, &anchor_id, &anchor_prv_key);
  anchor_bytes_size = encoder.offset;
```
We then step back into the role of the server, and make the controller the trust anchor (as a brief digression: though this is, again, covered thoroughly in the documentation, the trust anchor can be thought of as a certificate authority at the moment). 
```
  ndn_data_tlv_decode_no_verify(&anchor, encoder.output_value, encoder.offset, NULL, NULL);
  ndn_key_storage_set_trust_anchor(&anchor);
```
Continuing on as the server, we use the certificate given by the controller to generate a public and private key pair.
```
  ndn_ecc_pub_t* self_pub = NULL;
  ndn_ecc_prv_t* self_prv = NULL;
  ndn_key_storage_get_empty_ecc_key(&self_pub, &self_prv);
  ndn_ecc_make_key(self_pub, self_prv, NDN_ECDSA_CURVE_SECP256R1, 234);

```
We then pivot back to the controller's role. We must create a data packet that contains the certificate that the server will use.
```
 ndn_data_t self_cert;
  ndn_data_init(&self_cert);
  ndn_name_from_string(&self_cert.name, "/ndn-iot/bedroom/file-client/KEY", strlen("/ndn-iot/bedroom/file-client/KEY"));
  ndn_name_append_keyid(&self_cert.name, 890);
  ndn_name_append_string_component(&self_cert.name, "home", strlen("home"));
  ndn_name_append_keyid(&self_cert.name, 891);
  ndn_data_set_content(&self_cert, ndn_ecc_get_pub_key_value(self_pub),
                       ndn_ecc_get_pub_key_size(self_pub));
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &self_cert, &anchor_id, &anchor_prv_key);
```
Moving back to the server's side of things, we decode this certificate, and use it to set up our own identity using the certificate and the server's private key. 
```
  ndn_data_tlv_decode_no_verify(&self_cert, encoder.output_value, encoder.offset, NULL, NULL);
  ndn_key_storage_set_self_identity(&self_cert, self_prv);
  
```
To finish off the security initialization, we set up a verifier, which we'll use to check if interest packet's signatures can be verified. To be slightly more specific, it can be used to check if the signature interest packet was signed by an entity with a valid certificate from the trust anchor/controller.
```
  ndn_sig_verifier_init(&face->intf);
```
Lastly, we'll finish off the main method in exactly the same way we did in the earlier example.
```
  running = true;
  encoder_init(&encoder, buf, sizeof(buf));
  ndn_name_tlv_encode(&encoder, &name_prefix);
  ndn_forwarder_register_prefix(encoder.output_value, encoder.offset, on_interest, NULL);
  while(running){
    ndn_forwarder_process();
    usleep(10000);
  }

  ndn_face_destroy(&face->intf);
```

However, we're not quite done! The structure for on_interest will have to change to account for our ability and desire to verify interest packets. In order to properly do this, we'll take advantage of the function `ndn_sig_verifier_verify_int(interest, interest_size, &ek_interest, on_success, on_failure)` which will take in an interest and either run the `on_success` or `on_failure` method depending on whether the signature of the interest can be verified. 
Our `on_interest` function will now look something like this:
```
int on_interest(const uint8_t* interest, uint32_t interest_size, void* userdata){
  ndn_data_t data;
  ndn_encoder_t encoder;

  printf("On interest\n");
  ndn_sig_verifier_verify_int(interest, interest_size, &ek_interest, on_success, on_failure);
}
```
On a failure, our job is very easy! We simply report that the interest's signature couldn't be verified.
```
on_failure(ndn_interest_t* interest)
{
  printf("Cannot verify");
}
```
On a success, our job is slightly more difficult, but nothing we haven't seen before: we open the requested file, turn it into a data packet, and return it. This is functionally identical to the `on_interest` method in the first example. 
```
on_success(ndn_interest_t* interest)
{
  printf("verify succeed");
  char* file_name = interest->parameters.value;
  int param_size = interest->parameters.size;
  // tlv_parse_interest(interest,interest_size,3,
  //                    TLV_INTARG_NAME_PTR,&ek_name,TLV_INTARG_PARAMS_BUF,(uint8_t**)&file_name,
  //                    TLV_INTARG_PARAMS_SIZE,&param_size);
  file_name[param_size] = '\0';

  char temp_buffer[1024];
  FILE *fp = fopen(file_name,"r");
  printf("The requested file name is: %s\nlength is %d\n",file_name,param_size);
  if(fp == NULL){
    fprintf(stderr, "ERROR: fail to open file.\n");
    return;
  }
  if(fgets(temp_buffer,1024,fp) == NULL){
    fprintf(stderr, "ERROR: fail to read file.\n");
    return;
  }
```
This wraps up the tutorial on the server side of the simple file-transfer application with security. Just to recap, the process is essentially this: the server communicates with a controller/trust anchor, and acquires a public key, a private key, and a certificate. 
Seperately, it sets up a verifier, and checks interest packets to see if their signatures can be verified (in this case unsigned interest packets are also ignored, though one could easily imagine a different implementation). 

-----

With that in mind, we can take a look at the client side of the file-transfer application. Fortunately, now that we understand how the server works, this should be quite simple.

We start off in the same fashion as the server: we start ndn-lite, parse arguments, and do our security bootstrapping in exactly the same way the server did.
```
int main(int argc, char *argv[]){
  ndn_udp_face_t *face;
  ndn_interest_t interest;
  ndn_encoder_t encoder;
  int ret;

  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  ndn_lite_startup();

  // simulate bootstrapping process
  ndn_ecc_prv_t anchor_prv_key;
  ndn_ecc_prv_init(&anchor_prv_key, secp256r1_prv_key_str, sizeof(secp256r1_prv_key_str),
                   NDN_ECDSA_CURVE_SECP256R1, 123);
  ndn_data_t anchor;
  ndn_data_init(&anchor);
  ndn_name_from_string(&anchor.name, "/ndn-iot/controller", strlen("/ndn-iot/controller"));
  ndn_name_t anchor_id;
  memcpy(&anchor_id, &anchor.name, sizeof(ndn_name_t));
  ndn_name_append_string_component(&anchor.name, "KEY", strlen("KEY"));
  ndn_name_append_keyid(&anchor.name, 123);
  ndn_name_append_string_component(&anchor.name, "self", strlen("self"));
  ndn_name_append_keyid(&anchor.name, 456);
  ndn_data_set_content(&anchor, secp256r1_pub_key_str, sizeof(secp256r1_pub_key_str));
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &anchor, &anchor_id, &anchor_prv_key);
  anchor_bytes_size = encoder.offset;
  ndn_data_tlv_decode_no_verify(&anchor, encoder.output_value, encoder.offset, NULL, NULL);
  ndn_key_storage_set_trust_anchor(&anchor);

  // ndn_ecc_prv_t self_prv_key
  ndn_ecc_pub_t* self_pub;
  ndn_ecc_prv_t* self_prv;
  ndn_key_storage_get_empty_ecc_key(&self_pub, &self_prv);
  ndn_ecc_make_key(self_pub, self_prv, NDN_ECDSA_CURVE_SECP256R1, 890);

  // self cert
  ndn_data_t self_cert;
  ndn_data_init(&self_cert);
  ndn_name_from_string(&self_cert.name, "/ndn-iot/bedroom/file-client/KEY", strlen("/ndn-iot/bedroom/file-client/KEY"));
  ndn_name_append_keyid(&self_cert.name, 890);
  ndn_name_append_string_component(&self_cert.name, "home", strlen("home"));
  ndn_name_append_keyid(&self_cert.name, 891);
  ndn_data_set_content(&self_cert, ndn_ecc_get_pub_key_value(self_pub),
                       ndn_ecc_get_pub_key_size(self_pub));
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &self_cert, &anchor_id, &anchor_prv_key);
  ndn_data_tlv_decode_no_verify(&self_cert, encoder.output_value, encoder.offset, NULL, NULL);
  ndn_key_storage_set_self_identity(&self_cert, self_prv);

  // set up route
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, server_ip, port2);
  running = true;
  encoder_init(&encoder, buf, 4096);
  ndn_name_tlv_encode(&encoder, &name_prefix);
  ndn_forwarder_add_route(&face->intf, buf, encoder.offset);

  // set up sig verifier
  ndn_sig_verifier_init(&face->intf);

``` 

We do take a slight detour after setting up our verifier, however: the client needs to actually express an interest for the relevant file. This process is nearly identical to the one shown in the first tutorial, but in this case the client takes the added step of signing the interest (with a particular lifetime, in order to both reduce the attack surface and reduce the risk of repeat attacks). This is accomplished by the use of the `ndn_signed_interest_ecdsa_sign` function. 
```
  char interest_buf[4096];
  int interest_off;
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ndn_interest_t request;
  ndn_interest_from_name(&request, &name_prefix);
  ndn_interest_set_Parameters(&request, (uint8_t*)file_name, strlen(file_name));
  interest.lifetime = 10000;
  ndn_signed_interest_ecdsa_sign(&request, &storage->self_identity, self_prv);
  encoder_init(&encoder, interest_buf, 4096);
  ndn_interest_tlv_encode(&encoder, &request);
  ndn_forwarder_express_interest(interest_buf, encoder.offset, on_data, on_timeout, NULL);
```

Finally, we proceed in the normal fashion and run the forwarder.
```
  while(running){
    ndn_forwarder_process();
    usleep(10000);
  }

  ndn_face_destroy(&face->intf);

  return 0;
}
```
Lastly, we repeat the same `on_data` method that saves the requested file locally.
```
void on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata){
  ndn_data_t data;
  printf("Receiving data\n");
  // char data_buf[1024];
  char* data_buf;
  int data_off;
  tlv_parse_data(rawdata,data_size,2,TLV_DATAARG_CONTENT_BUF,(uint8_t**)&data_buf,TLV_DATAARG_CONTENT_SIZE,&data_off);
  //printf("data\n%s\n",data_buf);
  save_file(data_buf);
}
```
-----
That concludes this tutorial. Hopefully it was both clear and informative. Please direct any questions/comments to either hdellaverson@gmail.com or [Zhiyi Email Here]