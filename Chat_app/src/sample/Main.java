package sample;

public class Main {

    public static void main(String[] args) {
        // made by Youssef Danial Elwi
        // run this main twice to have two users
        // Also you can create as much as you want
        // allow multiple instance
        // Also make sure you type the same key because if you typed the key wrong you won't be able to read the messages
        // this is end to end encryption
        // this is a multi user chat application so i preferred that everyone want to chat was someone
        // they should choose a key for their own before starting chat and each one have the key can decrypt the messages
        // by doing this the security is at its highest because the server just work as a deliver
        // notice that your own message that shows in the gui is being received from the server before showing it
        // so while sending your message unencrypted to the server and trying to decrypted you want be able to see it
        // and the same for the other end client happen when you try to receive an unencrypted message and trying to decrypted
        // you won't be able to see the message
        // set your logic before using the decryption and encryption buttons on and off
        // Green indicate active while red indicate inactive
        // also there is an intentional delay have been put for 1s when receiving messages from the server
        client client_one = new client();
        //make sure to type a key that is 128 bit or 16 bytes 16 char or 24 chars or 32
        client_one.main(args);
        // notice that you can see all the traffic at the Server side
        // did not use pre_shared key because i think it is not a secure way of setting connections
        // using a known key from the clients is better as every time they can change it in every chatting session
        //=====================================================================================
        // pre sharing key function in brief
        // pre sharing only work with numbers passwords for now
        // pre sharing work as following
        // making a seed from the pasword that have been entered first 4 digits (i could made more complex things but it would take more time)
        // before sending the seed to the client send the server a message to indicate that he will send a seed to make the server be ready to receive it
        // using this seed the client would use MSM (mid square random number generator (self mid depending on my own understanding of it)) that would generate a random numers
        // this random number would be long so we will take only the first 16 digits and use them as the key for encryption and decryption
        // and sending the seed to the server that will send to all the clients that have a connection to the server in the time when the user press
        // pre-sharing button
        // after sending the seed the client who wanted to pre_share would make a encryption key from the same seed that have been sent to the other clients
        // and use this key to encrypt the real key and send it to the server to do the same with the key as the seed
        // after that the other clients and the sender himself would get the seed from the server and use it to make a key
        // that would be used to decrypt the real key
        // here what i did in example with simple graph
        // client that want to share -- client1
        // any other client that want to receive -- client2 
        // client1 (indication to the server) ===> server
        // client1 use(RealKey) generate (seed) ==> server (Seed)
        // client1 (use his seed to generate temp key using MSM)
        // Server (seed) ===> client1,client2 (Seed)
        // client1 (encrypted realKey with tempkey) ====> Server
        // Server(encrypted realKey with tempkey) ===> client1,2
        // client1,2 (use the seed by MSM to generate tempKey)
        // client1,2 (use the temp key to decrypt the realKey)
        // client1,2 set the real key as there main key
        // done
        // Best Wishes : Youssef Danial Elwi
    }
}


