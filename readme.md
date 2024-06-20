---
title: Updater Repository Tool

---

# Updater Repository Tool


- [The Update Framework (TUF)](https://theupdateframework.io/overview/) 
    - The Update Framework (TUF) is a framework for secure content delivery and updates. It protects against various types of supply chain attacks and provides resilience to compromise.
    - Resources:
        - [Official specifications](https://theupdateframework.github.io/specification/latest/)
        - [go-tuf](https://github.com/theupdateframework/go-tuf/): Implementation of TUF in Go programming language 

## Repository-Tool

![image](https://hackmd.io/_uploads/BkEY4mWLC.png)

`repository-tool` is a CLI program that provides different functionalities such as creating, updating and signing the different metadata files in TUF. It takes a folder of target files as input and RSA keys to generate metadata files that describe the hash and length of the target files. The metadata files will be versioned according to the TUF specifications.

Below are the commands provided by the tool coupled with descriptions and usage examples.

### 1. 4096-bit RSA key-pair generation (公私钥对生成)

Generates a pair of 4096-bit RSA keys, including a private key and a public key, both of which are written to 2 separate files respectively in pem format.

#### **Usage:**

`.\tool.exe keygen`
| Shortcut | Flags           | Type   | Description                               |
| -------- | --------------- | ------ | ----------------------------------------- |
| -h       | --help          |        |                                           |
| -d       | --output-dir    | string | Directory for output key files (required) |
| -v       | --priv-filename | string | Private key filename (required)           |
| -b       | --pub-filename  | string | Public key filename (required)            |

---

### 2. Initialization (初始化)

Initializes a new repository and outputs new metadata files, i.e. `1.root.json` / `1.targets.json` / `1.snapshot.json` / `timestamp.json`. The number that preceeds the metadata files is the version number, which will be `1` for a new repository.

#### **Usage:**

`.\tool.exe init`
| Shorcut | Flags                     | Type   | Description                                               |
| ------- | ------------------------- | ------ | --------------------------------------------------------- |
| -e      | --expire                  | uint16 | Metadata file expiration in days (required) (default 365) |
| -h      | --help                    |        |                                                           |
| -o      | --output-dir              | string | Directory for output metadata files (required)            |
| -d      | --repository-dir          | string | Directory containing target files (required)              |
| -v      | --root-priv-filepath      | string | Root private key filepath(s) (required)                   |
| -r      | --root-threshold          | uint8  | Root key threshold (required) (default 1)                 |
| -p      | --snapshot-priv-filepath  | string | Snapshot private key filepath(s) (required)               |
| -n      | --snapshot-threshold      | uint8  | Snapshot key threshold (required) (default 1)             |
| -x      | --targets-priv-filepath   | string | Targets private key filepath(s) (required)                |
| -g      | --targets-threshold       | uint8  | Targets key threshold (required) (default 1)              |
| -i      | --timestamp-priv-filepath | string | Timestamp private key filepath(s) (required)              |
| -s      | --timestamp-threshold     | uint8  | Timestamp key threshold (required) (default 1)            |

#### **Notes:**

- User has to provide 4 separate keys to sign the metadata file generated for each role, i.e. `root-private-key.pem`/`targets-private-key.pem`/`snapshot-private-key.pem`/`timestamp-private-key.pem`. It is possible to use the same key for every role, but this is not recommended.
- The threshold of keys should match the number of filepaths provided for each key, failure in doing so will result in an error. For example if `--root-threshold 2`, then `--root-priv-filepath ".\filepath1\priv1.pem;.\filepath\priv2.pem"`. Note the quotes `""` and semi-colon `;` for filepaths delimination.

#### **Example:**

```bashrc=
init \
    -d C:/target-files/ -o C:/output/ \
    -v "C:/key-files/rootPrivateKey;C:/key-files/rootPrivateKeyTwo" -r 2 \
    -x "C:/key-files/targetsPrivateKey;C:/key-files/targetsPrivateKeyTwo" -g 2 \
    -p C:/key-files/snapshotPrivateKey -n 1 \
    -i "C:/key-files/timestampPrivateKey;C:/key-files/timestampPrivateKeyTwo" -s 2 \
    -e 365
```

#### **Output:**
 4 metadata files i.e. `1.root.json` / `1.targets.json` / `1.snapshot.json` / `timestamp.json` in the directory specified by `--output-dir`.

---

### 3. Update （更新）

Updates and generates newer version (+1) of metadata files. A list of file changes will be shown for confirmation before writing to file. It is not necessary to have any file changes in order to generate the newer version, such as in the case of solely updating the expiration date of the metadata files.

#### **Usage:**

`.\tool.exe update`
| Shorcut | Flags                     | Type    | Description                                                                                       |
| ------- | ------------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| -c      | --ask-confirmation        | boolean | Ask for confirmation before proceeding (optional) (default true)                                  |
| -e      | --expire                  | uint16  | Metadata file expiration in days (required) (default 365)                                         |
| -h      | --help                    |         |                                                                                                   |
| -m      | --metadata-dir            | string  | Directory containing metadata files (required)                                                    |
| -d      | --repository-dir          | string  | Directory containing target files (required)                                                      |
| -s      | --snapshot-priv-filepath  | string  | Filepath of the private key for snapshot role (optional, but requires targets key)                |
| -r      | --targets-priv-filepath   | string  | Filepath of the private key for targets role (required)                                           |
| -t      | --timestamp-priv-filepath | string  | Filepath of the private key for timestamp role (optional, but requires snapshot and targets keys) |

#### **Notes:**

- User has to provide 3 private keys to sign the metadata file generated for `targets` / `snapshot` / `timestamp` roles. Only 1 key is for each role can be used to sign with the `update` command. If the sign threshold is more than 1, please use the `sign` command for the remaining signatures.
- It is possible to omit certain roles when signing:
    - Accepted combinations:
        | targets-key | snapshot-key | timestamp-key |
        |:-----------:|:------------:|:-------------:|
        |     ✅      |      ✅      |      ✅       |
        |     ✅      |      ✅      |      -       |
        |     ✅      |      -      |      -       |
    - The user has to complete the remaining signatures using the `sign` command.
- The `targets` / `snapshot` / `timestamp` expiration dates will be updated to `T+<-expire>` , where `T` is the current datetime. **`root`** metadata's **expiration date will not be updated**!

#### **Example:**

```bashrc=
update \
    -d C:/target-files/ -m C:/metadata-files/ \
    -r C:/key-files/targetsPrivateKey \
    -s C:/key-files/snapshotPrivateKey \
    -t C:/key-files/timestampPrivateKey \
    -e 365 
```

#### **Output:**

3 metadata files of newer version e.g. `2.targets.json` (new file) / `2.snapshot.json` (new file) / `timestamp.json` (overwrite existing file) in the directory specified by `--metadata-dir`.

---

### 4. Sign （签名）

Sign metadata file i.e. `root.json` / `targets.json` / `snapshot.json` / `timestamp.json` with private key.

#### **Usage:**

`.\tool.exe sign`
| Shorcut | Flags           | Type   | Description                                             |
| ------- | --------------- | ------ | ------------------------------------------------------- |
| -h      | --help          |        |                                                         |
| -m      | --metadata-dir  | string | Directory containing metadata files (required)          |
| -v      | --priv-filepath | string | Filepath of the private key for given role (required)   |
| -r      | --role          | string | Signing role targets/snapshot/timestamp/root (required) |
| -f        |   --forced              |  bool      |   Forced sign with unrecognized key (optional) (default false)                                                      |

#### **Notes:**

- Only 1 private key for 1 role is accepted for each `sign` command. For multiple roles/keys, call the `sign` commands separately.
- The private key provided must match its respective role.

#### **Example:**

```bashrc=
sign \
    -m C:/metadata-files/ \
    -v C:/key-files/targetsPrivateKey \
    -r targets
```

#### **Output:**

Write signature into the metadata file of the role specified. No new file is created.

---

### 5. Change-threshold （更改签名限制）

Change the signature threshold of role by increment or decrement. Applicable to all roles **except `root` role.**

#### **Usage:**

`.\tool.exe change-threshold`
| Shorcut | Flags                       | Type   | Description                                                                                   |
| ------- | --------------------------- | ------ | --------------------------------------------------------------------------------------------- |
| -a      | action                      | string | Threshold action: "add" or "reduce" (required)                                                |
| -h      | --help                      |        |                                                                                               |
| -m      | --metadata-dir              | string | Directory containing metadata files (required)                                                |
| -r      | --role                      | string | Role to change threshold targets/snapshot/timestamp (required)                                                           |
| -i      | --role-priv-filepath        | string | Filepath of the key for given role to be added(private)/removed(private or public) (required) |
| -v      | --root-priv-filepath string | string | Filepath of the private key for given role (required)                                         |

#### **Notes:**

- For case `action=add`, a new private key is required to increase the key threshold by 1.
- For case `action=reduce`, either the private key or public key to be revoked is accepted. The signature threshold will decrease by 1.
- Root private key is required in order to sign the newly updated root metadata file.

#### **Example:**

```bashrc=
sign \
    -m C:/metadata-files/ \
    -v C:/key-files/targetsPrivateKey \
    -r targets
```

#### **Output:**

Change signature threshold of the specified role in `root.json`. No new file is created.

---

### 6. Change Root Key (更换根密钥)

Add, remove or replace root key. This will increase or decrease the signature threshold of `root` role.

#### **Usage:**

`.\tool.exe change-root-key`
| Shorcut | Flags                 | Type   | Description                                                                             |
| ------- | --------------------- | ------ | --------------------------------------------------------------------------------------- |
| -a      | --action              | string | Action: "add" or "remove" (required)                                                    |
| -h      | --help                |        |                                                                                         |
| -i      | --input-priv-filepath | string | Filepath of another root key to be added(private)/removed(public or private) (required) |
| -m      | --metadata-dir        | string | Directory containing metadata files (required)                                          |
| -v      | --priv-filepath       | string | Filepath of the root private key for signing (required)                                 |
| -e      | --expire              | uint16 | Metadata file expiration in days (required) (default 365)                               |
| -t      | --threshold           | uint16 | Root key threshold (required)                                                           |

#### **Notes:**

- Supports 3 different actions, namely `add`/`remove`/`replace`, the required key combinations are shown below:
    | action  |                input-priv-filepath                 |     priv-filepath     | repl-priv-filepath |
    |:-------:|:--------------------------------------------------:|:---------------------:|:------------------:|
    |   add   |                 newRootPrivateKey                  | currentRootPrivateKey |         -          |
    | remove  | currentRootPrivateKeyTwo / currentRootPublicKeyTwo | currentRootPrivateKey |         -          |
    
    - The cases above assume that the current `root` signature threshold is 2, with 2 private keys namely `currentRootPrivateKey` and `currentRootPrivateKeyTwo`.
    
- `remove` action is not permitted for single-key case.

:::warning
On the client side, outdated root keys can update to the latest set of trusted root keys, by incrementally downloading all intermediate root metadata files, and verifying that each current version of the root metadata is signed by a threshold of keys specified by its immediate predecessor as well as a threshold of keys specified by itself. For example, if there is a **1.root.json** that has **threshold 2** and a **2.root.json** that has **threshold 3**, [**2.root.json MUST be signed by at least 2 keys defined in 1.root.json and at least 3 keys defined in 2.root.json**](https://theupdateframework.github.io/specification/latest/#key-management-and-migration).

**Please use `Sign` command to complete the key continuity.**
:::

#### **Example:**

```bashrc=
change-root-key \
    -a replace \
    -m C:/metadata-files/ \
    -i C:/key-files/rootPrivateKeyTwo \
    -v C:/key-files/rootPrivateKey \
    -r C:/key-files/newRootPrivateKey
```

#### **Output:**

Change signature threshold of the `root` role in `root.json`. No new file is created.

---

### 7. Verify （验证）

Verifies repository metadata files and targets, output the current state of the repository and issues to be fixed.

#### **Usage:**

`.\tool.exe sign`
| Shorcut | Flags            | Type   | Description                                    |
| ------- | ---------------- | ------ | ---------------------------------------------- |
| -h      | --help           |        |                                                |
| -m      | --metadata-dir   | string | Directory containing metadata files (required) |
| -d      | --repository-dir | string | Directory containing target files (required)   |

#### **Notes:**

- This command guarantees that the metadata files that passed the verification will be accepted on the client side.

#### **Example:**

```bashrc=
verify \
    -d C:/target-files/ \
    -m C:/metadata-files/
```

#### **Output:**

Print current status of the repository in the terminal. No new file is created.

---DATER

### Frameworks
- [TUF](https://theupdateframework.io/overview/) 
    - A framework that provides functionalities on  
- Realised Functionalities 已实现功能
    1. 4096-bit RSA key-pair generation （公私钥对生成）
    2. 