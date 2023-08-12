package client

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	ID        uuid.UUID
	Username  string
	Password  string
	SourceKey []byte // used for HashKDF and UUID
	PrivKey   userlib.PKEDecKey
	SigKey    userlib.DSSignKey
	AESKey    []byte
	HMACKey   []byte
	// store map of uuid->metadata
	FileMap      map[string]FileMetadata // maps filename to file's metadata
	InvitedMap   map[string]FileMetadata // maps keybox name to keybox metadata
	RecipientMap map[string]map[string]FileMetadata
	// nested map; maps filename to map of recipients; maps recipient username to keybox metadata
}

type File struct {
	ID                uuid.UUID
	Filename          string
	Owner             string
	FileSourceKey     []byte
	RevokeKey         []byte
	FileKey           []byte
	FileHMAC          []byte
	Head_content_id   uuid.UUID
	Head_content_key  []byte
	Head_content_hmac []byte
	Tail_content_id   uuid.UUID
	Tail_content_key  []byte
	Tail_content_hmac []byte
}

type FileContent struct {
	IsTail   bool
	ID       uuid.UUID
	Content  []byte // the actual plaintext content
	NextID   uuid.UUID
	NextKey  []byte
	NextHMAC []byte
}

type CipherPair struct {
	Ciphertext []byte
	Tag        []byte
}

type FileMetadata struct {
	ID   uuid.UUID
	Key  []byte
	HMAC []byte
}

type Invitation struct {
	ID uuid.UUID // HashKDF(sourcekey || sender username || recipient username || filename)
	// Revoked bool - moved to Keybox struct
	Inviter    string
	Recipient  string
	KeyboxID   uuid.UUID
	KeyboxKey  []byte
	KeyboxHMAC []byte
}

type Keybox struct {
	ID         uuid.UUID
	Name       string // original owner username + filename
	Revoked    bool
	KeyboxKey  []byte
	KeyboxHMAC []byte
	FileID     uuid.UUID
	FileKey    []byte
	FileHMAC   []byte
}

// Encrypt-then-MAC and add to DataStore
func StoreData(data []byte, id uuid.UUID, key []byte, hmac []byte) (err error) {
	IV := userlib.RandomBytes(16)
	var encryptedData CipherPair
	var _ error
	encryptedData.Ciphertext = userlib.SymEnc(key, IV, data)
	encryptedData.Tag, _ = userlib.HMACEval(hmac, encryptedData.Ciphertext)
	encryptedData_b, err := json.Marshal(encryptedData)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(id, encryptedData_b)
	return nil
}

// Fetch from DataStore, the verify tag and decrypt
// return decrypted plaintext
// caller will have to Unmarshal the plaintext
func FetchData(id uuid.UUID, key []byte, hmac []byte) (data []byte, err error) {
	var _ error
	encryptedData_b, ok := userlib.DatastoreGet(id)
	if !ok {
		return nil, errors.New("FetchData: DataStore does not contain specified uuid")
	}
	var encryptedData CipherPair
	_ = json.Unmarshal(encryptedData_b, &encryptedData)
	tag, _ := userlib.HMACEval(hmac, encryptedData.Ciphertext)
	equal := userlib.HMACEqual(tag, encryptedData.Tag)
	if !equal {
		return nil, errors.New("FetchData: tag does not match")
	}
	plaintext := userlib.SymDec(key, encryptedData.Ciphertext)
	return plaintext, nil
}

// creates a sentinel content node given uuid
func CreateSentinel(id uuid.UUID) (tail FileContent) {
	tail.IsTail = true
	tail.ID = id
	tail.Content = nil
	tail.NextID = id
	tail.NextKey = nil
	tail.NextHMAC = nil
	return tail
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("InitUser: username cannot be empty")
	}
	_, exists := userlib.KeystoreGet(username + "rsa")
	if exists {
		return nil, errors.New("InitUser: username is already taken")
	}
	var ret User
	var _ error // trivial error
	ret.Username = username
	ret.Password = password
	ret.SourceKey = userlib.Argon2Key([]byte(password), []byte(strings.Repeat(username, 64)), 16)
	ret.ID, _ = uuid.FromBytes(ret.SourceKey)
	pub, priv, _ := userlib.PKEKeyGen()
	ret.PrivKey = priv
	userlib.KeystoreSet(username+"rsa", pub)
	priv, pub, _ = userlib.DSKeyGen()
	ret.SigKey = priv
	userlib.KeystoreSet(username+"sign", pub)
	AESKey, _ := userlib.HashKDF(ret.SourceKey, []byte("aes"))
	ret.AESKey = AESKey[:16]
	HMACKey, _ := userlib.HashKDF(ret.SourceKey, []byte("hmac"))
	ret.HMACKey = HMACKey[:16]
	ret.FileMap = make(map[string]FileMetadata)
	ret.InvitedMap = make(map[string]FileMetadata)
	ret.RecipientMap = make(map[string]map[string]FileMetadata)
	// encrypt then mac and add to datastore
	ret_b, err := json.Marshal(ret)
	if err != nil {
		return nil, err
	}
	StoreData(ret_b, ret.ID, ret.AESKey, ret.HMACKey)
	// userlib.DebugMsg("InitUser: %v", ret.Username)
	return &ret, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	SourceKey := userlib.Argon2Key([]byte(password), []byte(strings.Repeat(username, 64)), 16)
	id, _ := uuid.FromBytes(SourceKey)
	AESKey, _ := userlib.HashKDF(SourceKey, []byte("aes"))
	AESKey = AESKey[:16]
	HMACKey, _ := userlib.HashKDF(SourceKey, []byte("hmac"))
	HMACKey = HMACKey[:16]
	user_b, err := FetchData(id, AESKey, HMACKey)
	if err != nil || user_b == nil {
		return nil, err
	}
	var userdata User
	err = json.Unmarshal(user_b, &userdata)
	if err != nil {
		return nil, err
	}
	// userlib.DebugMsg("GetUser: %v", userdata.Username)
	return &userdata, nil
}

// Creates a new file and sets attributes. Then stores file and contents in DataStore
func InitFile(filename string, owner string, content []byte) (file File) {
	file.Filename = filename
	file.Owner = owner
	FileSourceKey := userlib.Argon2Key([]byte(filename), []byte(strings.Repeat(owner, 64)), 16)
	file.FileSourceKey = FileSourceKey
	id, _ := uuid.FromBytes(FileSourceKey)
	file.ID = id
	file.RevokeKey = userlib.RandomBytes(16)
	FileKey, _ := userlib.HashKDF(FileSourceKey, append([]byte("aes"), file.RevokeKey...))
	file.FileKey = FileKey[:16]
	FileHMAC, _ := userlib.HashKDF(FileSourceKey, append([]byte("hmac"), file.RevokeKey...))
	file.FileHMAC = FileHMAC[:16]
	/* Set content keys to random values.
	When access is revoked, we will consolidate file content
	into one big content struct and assign a new File ID. */
	file.Head_content_id = uuid.New()
	file.Head_content_key = userlib.RandomBytes(16)
	file.Head_content_hmac = userlib.RandomBytes(16)
	file.Tail_content_id = uuid.New()
	file.Tail_content_key = userlib.RandomBytes(16)
	file.Tail_content_hmac = userlib.RandomBytes(16)

	var HeadContent FileContent
	HeadContent.IsTail = false
	HeadContent.ID = file.Head_content_id
	HeadContent.Content = content // lol
	HeadContent.NextID = file.Tail_content_id
	HeadContent.NextKey = file.Tail_content_key
	HeadContent.NextHMAC = file.Tail_content_hmac

	// create sentinel content node and set as tail
	TailContent := CreateSentinel(file.Tail_content_id)

	// store content nodes and file in DataStore
	HC_b, _ := json.Marshal(HeadContent)
	TC_b, _ := json.Marshal(TailContent)
	file_b, _ := json.Marshal(file)

	StoreData(HC_b, file.Head_content_id, file.Head_content_key, file.Head_content_hmac)
	StoreData(TC_b, file.Tail_content_id, file.Tail_content_key, file.Tail_content_hmac)
	StoreData(file_b, file.ID, file.FileKey, file.FileHMAC)

	return file
}

// given file struct set the content
func SetContent(file File, content []byte) (err error) {
	headContent_b, err := FetchData(file.Head_content_id, file.Head_content_key, file.Head_content_hmac)
	if err != nil {
		return err
	}
	var headContent FileContent
	err = json.Unmarshal(headContent_b, &headContent)
	if err != nil {
		return err
	}
	headContent.Content = content
	headContent.NextID = file.Tail_content_id
	headContent.NextKey = file.Tail_content_key
	headContent.NextHMAC = file.Tail_content_hmac

	// add updated headContent to DataStore
	headContent_b, _ = json.Marshal(headContent)
	StoreData(headContent_b, file.Head_content_id, file.Head_content_key, file.Head_content_hmac)

	return nil
}

func GetFile(userdata *User, filename string) (metadata FileMetadata, exists bool, err error) {
	fmetadata, exists := userdata.FileMap[filename]
	if exists {
		return fmetadata, true, nil
	}

	kbMetadata, exists := userdata.InvitedMap[filename]
	if exists {
		kb_b, err := FetchData(kbMetadata.ID, kbMetadata.Key, kbMetadata.HMAC)
		if err != nil {
			return fmetadata, false, err
		}
		var kb Keybox
		err = json.Unmarshal(kb_b, &kb)
		if err != nil {
			return fmetadata, false, err
		}
		var ret FileMetadata
		ret.ID = kb.FileID
		ret.Key = kb.FileKey
		ret.HMAC = kb.FileHMAC
		return ret, true, nil
	}
	return fmetadata, false, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("this should not happen")
	}

	// metadata, exists := userdata.FileMap[filename]
	metadata, exists, err := GetFile(userdata, filename)
	if err != nil {
		return err
	}
	// must preserve id if file already exists in user namespace
	if !exists {
		var newFile File // the actual file attributed to filename
		newFile = InitFile(filename, userdata.Username, content)
		var newMetadata FileMetadata
		newMetadata.ID = newFile.ID
		newMetadata.Key = newFile.FileKey
		newMetadata.HMAC = newFile.FileHMAC
		userdata.FileMap[filename] = newMetadata
		// userlib.DebugMsg("StoreFile: %v stored (%v) in %v", userdata.Username, string(content), filename)
		// userlib.DebugMsg("Filemap newMetadata: %v", &newMetadata)
	} else {
		var file File
		file_b, err := FetchData(metadata.ID, metadata.Key, metadata.HMAC)
		if err != nil {
			return err
		}
		err = json.Unmarshal(file_b, &file)
		if err != nil {
			return err
		}
		err = SetContent(file, content)
		if err != nil {
			return err
		}
	}
	userdata_b, _ := json.Marshal(userdata)
	StoreData(userdata_b, userdata.ID, userdata.AESKey, userdata.HMACKey)
	return nil
}

func AppendContent(file File, content []byte) (err error) {
	newTail := CreateSentinel(uuid.New()) // new tail

	oldTail_b, err := FetchData(file.Tail_content_id, file.Tail_content_key, file.Tail_content_hmac)
	var oldTail FileContent // old tail
	err = json.Unmarshal(oldTail_b, &oldTail)
	if err != nil {
		return err
	}

	oldTailKey := file.Tail_content_key
	oldTailHMAC := file.Tail_content_hmac

	file.Tail_content_id = newTail.ID
	file.Tail_content_key = userlib.RandomBytes(16)
	file.Tail_content_hmac = userlib.RandomBytes(16)

	oldTail.IsTail = false
	oldTail.Content = content
	oldTail.NextID = newTail.ID
	oldTail.NextKey = file.Tail_content_key
	oldTail.NextHMAC = file.Tail_content_hmac

	// store the oldTail, newTail, and file in DataStore
	oldTail_b, _ = json.Marshal(oldTail)
	newTail_b, _ := json.Marshal(newTail)
	file_b, _ := json.Marshal(file)

	StoreData(oldTail_b, oldTail.ID, oldTailKey, oldTailHMAC)
	StoreData(newTail_b, file.Tail_content_id, file.Tail_content_key, file.Tail_content_hmac)
	StoreData(file_b, file.ID, file.FileKey, file.FileHMAC)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return errors.New("this should not happen")
	}

	// metadata, exists := userdata.FileMap[filename]
	metadata, exists, err := GetFile(userdata, filename)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("AppendToFile: file does not exist in user's namespace")
	}
	file_b, err := FetchData(metadata.ID, metadata.Key, metadata.HMAC)
	if err != nil {
		return err
	}
	var file File
	err = json.Unmarshal(file_b, &file)
	if err != nil {
		return err // will error wihtout correct decryption key (credentials)
	}

	/* this helper will automatically append content and store
	   updated contents and file to DataStore */
	err = AppendContent(file, content)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("AppendFile: %v appended (%v) in %v", userdata.Username, string(content), filename)
	return nil
}

func MergeContent(contentNode FileContent) (content []byte, err error) {
	totalContent := []byte{}
	node := contentNode
	for i := 0; i > -1; i++ { // infinite loop
		if node.IsTail {
			break
		}
		totalContent = append(totalContent, node.Content...)
		next_b, err := FetchData(node.NextID, node.NextKey, node.NextHMAC)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(next_b, &node)
		if err != nil {
			return nil, err
		}
	}
	return totalContent, nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}

	// metadata, exists := userdata.FileMap[filename]
	metadata, exists, err := GetFile(userdata, filename)
	if err != nil {
		return nil, err
	}
	// userlib.DebugMsg("LoadFile: file %v exists = %v", filename, exists)
	if !exists {
		return nil, errors.New("LoadFile: file does not exist in user's namespace")
	}

	file_b, err := FetchData(metadata.ID, metadata.Key, metadata.HMAC)
	// userlib.DebugMsg("LoadFile: FetchData errors = %v", err != nil)
	if err != nil {
		return nil, err
	}
	var file File
	err = json.Unmarshal(file_b, &file)
	if err != nil {
		return nil, err // will error wihtout correct decryption key (credentials)
	}

	contentNode_b, err := FetchData(file.Head_content_id, file.Head_content_key, file.Head_content_hmac)
	if err != nil {
		return nil, err
	}
	var contentNode FileContent
	err = json.Unmarshal(contentNode_b, &contentNode)
	if err != nil {
		return nil, err
	}

	// consolidate contents
	totalContent, err := MergeContent(contentNode)
	// userlib.DebugMsg("LoadFile: MergeContent errors = %v", err != nil)
	if err != nil {
		return nil, err
	}
	return totalContent, nil
}

type SignPair struct {
	Ciphertext []byte
	Signature  []byte
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// get most up-to-date userdata
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, err
	}

	// metadata, exists := userdata.FileMap[filename]
	metadata, exists, err := GetFile(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}
	// userlib.DebugMsg("Invite: file %v exists = %v", filename, exists)
	if !exists {
		return uuid.Nil, errors.New("CreateInvitation: file does not exist in user's namespace")
	}
	// get recipient's public keys
	PubKey, ok := userlib.KeystoreGet(recipientUsername + "rsa")
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: recipient does not exist")
	}
	// userlib.DebugMsg("CreateInvitation: %v RSA public key = %v", recipientUsername, PubKey)
	// fetch the file
	file_b, err := FetchData(metadata.ID, metadata.Key, metadata.HMAC)
	if err != nil {
		return uuid.Nil, err
	}
	var file File
	err = json.Unmarshal(file_b, &file)
	if err != nil {
		return uuid.Nil, err
	}

	// create invatation and keybox
	// if is owner of file, create new keybox
	// else, set the invatation attributes to the kbMetadata fields
	var kb Keybox
	kbMetadata, invited := userdata.InvitedMap[filename]
	if !invited { // user is the original owner of the file
		kb.ID = uuid.New()
		kb.Name = userdata.Username + filename
		kb.Revoked = false
		kb.KeyboxKey = userlib.RandomBytes(16)
		kb.KeyboxHMAC = userlib.RandomBytes(16)
		kb.FileID = file.ID
		kb.FileKey = file.FileKey
		kb.FileHMAC = file.FileHMAC

	} else { // user is not the original owner of the file
		// only need to set the ID, Key, and HMAC (other fields are trivial)
		kb.ID = kbMetadata.ID
		kb.Name = ""
		kb.Revoked = false
		kb.KeyboxKey = kbMetadata.Key
		kb.KeyboxHMAC = kbMetadata.HMAC
		kb.FileID = uuid.Nil
		kb.FileKey = nil
		kb.FileHMAC = nil
	}

	// always create new invitation
	// set the keybox fields to either the newly created KB (is owner) or a
	// pre-existing KB (is invitee)

	// i think the bug is that the invite struct is too large for PKEDec so
	// we should store the invite struct in data store and just return a metadata
	var invite Invitation
	// may have to user slow hash to hide the filename
	// IDKey, _ := userlib.HashKDF(userdata.SourceKey, []byte(userdata.Username + recipientUsername + filename))
	invite.ID = uuid.New()
	invite.Inviter = userdata.Username
	invite.Recipient = recipientUsername
	invite.KeyboxID = kb.ID
	invite.KeyboxKey = kb.KeyboxKey
	invite.KeyboxHMAC = kb.KeyboxHMAC

	// store keybox in DataStore only if it's newly created (is owner)
	// pre-existing keyboxs are already in DataStore and are unmodified by CreateInvitation
	if !invited {
		kb_b, _ := json.Marshal(kb)
		StoreData(kb_b, kb.ID, kb.KeyboxKey, kb.KeyboxHMAC)
		// create recipient metadata and add to recipient map
		var rMetadata FileMetadata // metadata of keybox to be added to recipient map
		rMetadata.ID = kb.ID
		rMetadata.Key = kb.KeyboxKey
		rMetadata.HMAC = kb.KeyboxHMAC
		rmap, exists := userdata.RecipientMap[filename]
		if !exists {
			userdata.RecipientMap[filename] = make(map[string]FileMetadata)
			userdata.RecipientMap[filename][recipientUsername] = rMetadata
		} else {
			rmap[recipientUsername] = rMetadata
		}

		// store updated userdata
		userdata_b, _ := json.Marshal(userdata)
		StoreData(userdata_b, userdata.ID, userdata.AESKey, userdata.HMACKey)
	}

	// create a metadata struct to store the invitation in DataStore
	// using normal AES-HMAC method
	var inviteMetadata FileMetadata
	inviteMetadata.ID = invite.ID
	inviteMetadata.Key = userlib.RandomBytes(16)
	inviteMetadata.HMAC = userlib.RandomBytes(16)

	// store the invitation using the metadata fields
	invite_b, err := json.Marshal(invite)
	err = StoreData(invite_b, inviteMetadata.ID, inviteMetadata.Key, inviteMetadata.HMAC)
	if err != nil {
		return uuid.Nil, err
	}

	// encrypt and sign the metadata
	// store in datastore with a randon uuid
	// return that uuid
	inviteMetadata_b, _ := json.Marshal(inviteMetadata)
	encryptedIM_b, err := userlib.PKEEnc(PubKey, inviteMetadata_b)
	if err != nil {
		return uuid.Nil, err
	}
	// sign the encrypted invite metadata
	signature_b, _ := userlib.DSSign(userdata.SigKey, encryptedIM_b)
	var signedIM SignPair
	signedIM.Ciphertext = encryptedIM_b
	signedIM.Signature = signature_b
	signedIM_b, _ := json.Marshal(signedIM)
	IM_id := uuid.New()
	userlib.DatastoreSet(IM_id, signedIM_b)

	return IM_id, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	// get most up-to-date userdata
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}

	// metadata, exists := userdata.FileMap[filename]
	metadata, exists, err := GetFile(userdata, filename)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("AcceptInvitation: filename already exists in recipient's namespace")
	}
	// fetch the invitation metadata
	signedInvite_b, ok := userlib.DatastoreGet(invitationPtr) // this is a SignPair_b type
	if !ok {
		return errors.New("AcceptInvitation: InvitationPtr does not exist in DataStore")
	}
	// get rsa decryption key and public signature verification key
	privKey := userdata.PrivKey
	// userlib.DebugMsg("AcceptInvite: %v Private RSA key = %v", userdata.Username, privKey)
	signVerifyKey, ok := userlib.KeystoreGet(senderUsername + "sign")
	if !ok {
		return errors.New("AcceptInvitation: senders signature key does not exist in KeyStore")
	}
	// unmarshal the SignPair and check its signature
	var signedInvite SignPair
	err = json.Unmarshal(signedInvite_b, &signedInvite)
	if err != nil {
		return err
	}

	err = userlib.DSVerify(signVerifyKey, signedInvite.Ciphertext, signedInvite.Signature)
	if err != nil {
		return err
	}
	// decrypt the SignPair's ciphertext using recipient's rsa key
	IM_b, err := userlib.PKEDec(privKey, signedInvite.Ciphertext)
	if err != nil {
		return err
	}
	var IM FileMetadata // plain invitationMetadata struct
	err = json.Unmarshal(IM_b, &IM)
	if err != nil {
		return err
	}
	// from the invite metadata get the invite struct. then from the invite get the keybox
	invite_b, err := FetchData(IM.ID, IM.Key, IM.HMAC)
	if err != nil {
		// IM.ID is nil here
		userlib.DebugMsg("Invitation is nil: %v", invitationPtr == uuid.Nil)
		userlib.DebugMsg("InvitationID is nil: %v", IM.ID == uuid.Nil)
		return errors.New("FetchData: LINE 734!!!")
		return err
	}
	var invite Invitation
	err = json.Unmarshal(invite_b, &invite)
	if err != nil {
		return err
	}
	// we finally have the invatation struct and can get the keybox
	kb_b, err := FetchData(invite.KeyboxID, invite.KeyboxKey, invite.KeyboxHMAC)
	if err != nil {
		return err
	}
	var kb Keybox
	err = json.Unmarshal(kb_b, &kb)
	if err != nil {
		return err
	}
	if kb.Revoked {
		return errors.New("AcceptInvitation: Invitation has already been revoked")
	}

	// add Keybox metadata to invited list
	metadata.ID = kb.ID
	metadata.Key = kb.KeyboxKey
	metadata.HMAC = kb.KeyboxHMAC
	userdata.InvitedMap[filename] = metadata

	// add file data to user's filemap
	// metadata.ID = kb.FileID
	// metadata.Key = kb.FileKey
	// metadata.HMAC = kb.FileHMAC
	// userdata.FileMap[filename] = metadata

	userdata_b, _ := json.Marshal(userdata)
	StoreData(userdata_b, userdata.ID, userdata.AESKey, userdata.HMACKey)

	return nil
}

/*
	 need to change Revoke variable to false. also move revoke bool to keybox struct
		instead of invite. then generate a new revoke key and update the file key and hmac.
		share this new key and hmac to all the other keyboxes. need to change location (uuid)
		of file and contents. can easily do this by merging the content, then chaanging the
		head uuid and tail uuid.
*/
func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	// metadata, exists := userdata.FileMap[filename]
	metadata, exists, err := GetFile(userdata, filename)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("RevokeAccess: file is not in user's namespace")
	}
	file_b, err := FetchData(metadata.ID, metadata.Key, metadata.HMAC)
	if err != nil {
		// userlib.DebugMsg("FetchData 0")
		return err
	}
	var file File
	err = json.Unmarshal(file_b, &file)
	if err != nil {
		return err
	}
	if file.Owner != userdata.Username {
		return errors.New("RevokeAccess: user does not have ownership of file")
	}

	// fmap maps username to keybox metadata for file filename
	fmap, exists := userdata.RecipientMap[filename]
	if !exists {
		return errors.New("RevokeAccess: file is not currently shared with anyone")
	}
	kbMetadata, exists := fmap[recipientUsername]
	if !exists {
		return errors.New("RevokeAccess: file is not currently shared with recipient")
	}
	kb_b, err := FetchData(kbMetadata.ID, kbMetadata.Key, kbMetadata.HMAC)
	if err != nil {
		// userlib.DebugMsg("FetchData 1")
		return err
	}
	var kb Keybox
	err = json.Unmarshal(kb_b, &kb)
	if err != nil {
		return err
	}
	kb.Revoked = true
	kb_b, err = json.Marshal(kb)
	StoreData(kb_b, kbMetadata.ID, kbMetadata.Key, kbMetadata.HMAC)

	// remove recipient's kb metadata from fmap
	delete(fmap, recipientUsername) // BUG HERE I THINK

	// ===== updating file attributes =====
	// merge the file content
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	err = userdata.StoreFile(filename, content)
	if err != nil {
		return err
	}
	// delete old file entry from datastore
	userlib.DatastoreDelete(file.ID)
	// change the file id
	file.ID = uuid.New()
	// generate new filekeys and move the file to a new location
	file.RevokeKey = userlib.RandomBytes(16)
	FileKey, _ := userlib.HashKDF(file.FileSourceKey, append([]byte("aes"), file.RevokeKey...))
	file.FileKey = FileKey[:16]
	FileHMAC, _ := userlib.HashKDF(file.FileSourceKey, append([]byte("hmac"), file.RevokeKey...))
	file.FileHMAC = FileHMAC[:16]
	file_b, err = json.Marshal(file)
	if err != nil {
		return err
	}
	err = StoreData(file_b, file.ID, file.FileKey, file.FileHMAC)
	if err != nil {
		return err
	}
	var newMetadata FileMetadata
	newMetadata.ID = file.ID
	newMetadata.Key = file.FileKey
	newMetadata.HMAC = file.FileHMAC
	userdata.FileMap[filename] = newMetadata

	// v is the kb metadata
	// for each metadata in fmap, update the file id and keys
	for _, v := range fmap {
		kb_b, err = FetchData(v.ID, v.Key, v.HMAC)
		if err != nil {
			// userlib.DebugMsg("FetchData 2")
			return err
		}
		err = json.Unmarshal(kb_b, &kb)
		if err != nil {
			return err
		} // kb is now the actual kb struct of the other invitees
		kb.FileID = file.ID
		kb.FileKey = file.FileKey
		kb.FileHMAC = file.FileHMAC
		kb_b, err = json.Marshal(kb)
		if err != nil {
			return err
		}
		err = StoreData(kb_b, v.ID, v.Key, v.HMAC)
		if err != nil {
			return err
		}
	}

	userdata_b, _ := json.Marshal(userdata)
	StoreData(userdata_b, userdata.ID, userdata.AESKey, userdata.HMACKey)

	return nil
}
