## The Mnemonic Vault

The mnemonic vault is a layer zero (L0) vault for creating secure archives where only the owner can access their contents.

## Why does this exist?

Currently, files are insecure by default regardless of their content or type (Arm, x86, etc.). What do I mean by this? Let's suppose you want to have a cryptocurrency wallet. You generate the recovery words to generate the private key, and decide to store them in a .txt file (default text extension.) And have the brilliant idea of ​​storing them in a digital vault like (Bitwarden, OnePassword, etc.). You may think they are safe, but without realizing it, you are already exposing your wallet to risk, and trusting third parties not to read your data. What I propose is to have an easy way to create copies that are secure vaults in themselves where only the owner can open them. If every computer file were secure by default on any target machine, many leaks and property damage would be avoided. So I decided to create this, thinking that even if you share your private key on your Twitter, if it is protected with this, **then it will be the same as nothing**.

## But doesn't that already exist?

You might think that this is basically like zipping a file and putting a password on it. And you're right, but what I'm proposing is that you turn your naked file into a safe by default, in a simple, standardized way (which zips, .zip, .rar, .7zip, etc. are not) and secure. Answer me honestly, do you encrypt your files before storing them? I don't think so. That's why if there's a leak, you'll be compromised.

Here's an analogy: have you ever seen a car without a security system? Have you ever seen a car without locks, alarm systems, or keys? Exactly! Why are your files insecure by default? If someone hacks into your L1 system that you use to store your naked files, they'll have them, but what if each file was a safe in itself? **Good luck trying passwords for the next 100 years**.

## But won't that make sharing and execution more difficult?

You might think that adding an extra step to a file will make everything more bureaucratic and complex, but I decided to keep things as simple as a simple json file (that's literally it) take a look:

```rs
// src/core/parser.rs
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}
```

As you can see, the final file has three sections:

- `salt`: Essential for KDFs, ensuring that even if two users choose the same password, their derived keys will be different, preventing precomputation attacks.

- `nonce`: A "number used once", essential for AES-GCM to ensure that encrypting the same plaintext with the same key produces different ciphertexts, increasing security.

- `ciphertext`: The actual encrypted content of the original file.

And that's it, with just that your naked file has been transformed into a secure safe with secure locks (as secure as `AES-256-GCM` military encryption is widely used in military and international systems.) where only you can open this safe and access the file, be it a text file, a photo, a pdf document or even a program.

With this simplicity you can even write your own parser and decryption system you don't need to depend on this tool for that, I don't want to sell a product just contribute with an idea so I decided to keep things as simple as possible, you can extend this, instead of a simple `json` or `bjson` you could have your own file with special sections added by yourself or make a patch in the file encrypting the `.text`, `.data` and `.code` sections and creating sections to store the `salt` and `nonce` thus creating your own custom secure file extension something like `.vault` or something similar, if you have time you can implement a `zip` system to compress the data making the final file smaller and maintaining security, anyway there are many possible extensions that could be implemented I chose to keep it as simple as possible to serve as a proof of concept of an idea.

## How to build/install

Now that I have presented my idea and put my arguments as to why I built this, I will leave below a simple tutorial to install this tool. After all, there is no dark magic here. This is an executable Rust binary like any other. You can even build it from scratch if you want. Just have Rust installed, resolve the dependencies and compile for your architecture:

### For install

```sh
$ cargo install mnemonic-vault
```

> Yes, you need to have Rust and Cargo installed.

### For build from source

```sh
# 1. Clone the repository
$ git clone https://github.com/0x41337/mnemonic-vault.git

# 2. Enter the work directory
$ cd mnemonic-vault

# 3. Build the project
$ cargo build --release

# You should find the command line executable at: target/release/mnemonic-vault
```

### How to use

The operation is simple: you can lock a file (turn it into a self-contained safe) or unlock a safe (open a safe that you have previously locked). In short, you will have two commands:

- `lock`: As the name suggests, this locks the file.
- `unlock`: As the name also suggests, this unlocks a file.

#### Example

Imagine that I generated a Bitcoin wallet and I want to store this wallet online but I don't want to be hacked and lose all my money, so I save the keywords to generate the private key in a file:

```sh
$ ls
# secret.txt ./ ../
```

As you can see our `secret.txt` is the little guy that contains our words that can rebuild our Bitcoin wallet, now we create a safe copy of this file:

```sh
$ mnemonic-vault lock --target secret.txt
```

The program will ask me for a recovery phrase (in a sentence, a phrase is harder to guess than a password.) I pass the password then it generates our file:

```sh
$ ls
# secret.txt secret.txt.lock ./ ../
```

let's take a look at our file?

```sh
$ cat secret.txt.lock
```

> The output is:

```json
{
  "salt": "aGVsbG9zb2x0aGVyZQ==",
  "nonce": "n3xj7LDfZUc=",
  "ciphertext": "3a+8T2xuN3wDzV6N6Rk=..."
}
```

> Vaults are perpetual archives. Whoever holds the phrase, holds the content. Like smart contracts, they are versionless, they do not change, and their structure is public and immutable. Simplicity and security.

Now we can delete our naked file and keep our safe copy (yes, it was made with the idea of ​​having only one copy and it being safe in mind). You can delete the original file to avoid leaks. The entire process is reversible, as long as you have the recovery phrase:

```sh
$ rm secret.txt
$ ls
# secret.txt.lock ./ ../
```

Now you have a file protected at level 0 (in principle, that is, the file itself is protected). Now you can be even more paranoid when it comes to security and saving this secure copy in a L1 solution (layer 1, that is, above the file, for example, a file system). Something like Bitwarden or OnePassword, choose whatever you want. Even if they try to read it, they won't be able to, and if it leaks for some reason, it doesn't pose a big risk because the file is protected in principle. That's it. I thank everyone who read this far.

## License

The code is licensed under the `MIT` license. Please check the license file to make sure you understand everything before using it.
