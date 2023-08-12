package client_test

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	"strings"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	// Helper function to measure bandwidth of a particular operation
	measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}

	Describe("Advanced Tests", func() {
		Specify("Usernames and Password Test 1: the username must be unique.", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that each user has a unique username.")
			alicePhone, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Usernames and Password Test 2: the username must have a length greater than zero.", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that each user has a usernames of any length greater than zero.")
			bob, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Usernames and Password Test 3: Usernames are case-sensitive", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			Alice1, err := client.InitUser("Alice", defaultPassword+"1")
			_ = Alice1 // get rid of compiler error
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			Alice1, err = client.GetUser("Alice", defaultPassword+"1")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try getting user Alice with user alice's password.")
			Alice1, err = client.GetUser("Alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Try getting user alice with user Alice's password.")
			alice, err = client.GetUser("alice", defaultPassword+"1")
			Expect(err).ToNot(BeNil())
		})

		Specify("Usernames and Password Test 4: The client MUST NOT assume each user has a unique password.", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Usernames and Password Test 5: The client SHOULD support passwords length greater than or equal to zero", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", "")
			Expect(err).To(BeNil())
		})

		Specify("Usernames and Password Test 6: Try to get the user with wrong password", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try to get user with wrong password.")
			alice, err = client.InitUser("alice", "Wrongpassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("User Session test 1: The client MUST support a single user having multiple active sessions at the same time.", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentOne)
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice to alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data using alicePhone: %s", contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file ...")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("User Session test 2: Try to obtain the user session that doesn't exist.", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("try to get user session that doesn't exist.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Storing file data using the user session that doesn't exist: %s", contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("User Session test 3: Changing user data", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userMap := make(map[userlib.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				userMap[key] = val
			}

			for key, _ := range userMap {
				userlib.DatastoreDelete(key)
				userlib.DatastoreSet(key, []byte(contentOne))
			}

			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Files Test 1: Filenames MAY be any length, including zero (empty string).", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile("", []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile("", []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile("", []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Files Test 2: The client MUST NOT assume that filenames are globally unique.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob storing file %s with content: %s", aliceFile, contentOne)
			err = bob.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", aliceFile, contentTwo)
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alice sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Files Test 3: Try to obtain the file that doesn't exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Try to obtain the file that doesn't exist: %s", "abcd")
			_, err = alice.LoadFile("abcd")
			Expect(err).ToNot(BeNil())
		})

		Specify("Files Test 4: Modify the dataStore after storing the file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Modify DataStore.")
			for key, value := range userlib.DatastoreGetMap() {
				value[32] = byte(64)
				userlib.DatastoreSet(key, value)
			}

			userlib.DebugMsg("Load file data: %s", contentOne)
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Files Test 5: Clear the dataStore after Storing a file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			userlib.DebugMsg("Load file data: %s", contentTwo)
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Files Test 6: Testing the integrity of file struct", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			beforeMap := userlib.DatastoreGetMap()

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			var newUUID userlib.UUID
			afterMap := userlib.DatastoreGetMap()
			for key := range afterMap {
				if string(beforeMap[key]) != string(afterMap[key]) {
					newUUID = key
				}
			}

			userlib.DatastoreSet(newUUID, []byte(contentTwo))
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Files Test 7: Change the byte in dataStore", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userMap := make(map[userlib.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				userMap[key] = val
			}

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			fileMap := make(map[userlib.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				if _, found := userMap[key]; !found {
					fileMap[key] = val
				}
			}

			// modify the file struct
			for key, val := range fileMap {
				userlib.DatastoreDelete(key)
				userlib.DatastoreSet(key, append(val, byte(0)))
			}

			userlib.DebugMsg("Load file data: %s", contentOne)
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.KeystoreClear()
			userlib.DatastoreClear()

			userlib.DebugMsg("Initializing user Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// Obtain the bob user struct
			userMap1 := make(map[userlib.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				userMap1[key] = val
			}

			userlib.DebugMsg("bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// Obtain the bob file struct
			fileMap1 := make(map[userlib.UUID][]byte)
			for key, val := range userlib.DatastoreGetMap() {
				if _, found := userMap1[key]; !found {
					fileMap1[key] = val
				}
			}

			// delete file struct
			Expect(fileMap).ToNot(Equal(fileMap1))
			for key, _ := range fileMap1 {
				userlib.DatastoreDelete(key)
				userlib.DatastoreSet(key, []byte(contentOne))
			}

			userlib.DebugMsg("Load file data: %s", contentOne)
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 1: Clear the DataStore after initializing the user", func() {
			userlib.DebugMsg("Initializing user alice.")
			_, err := client.InitUser("alice", "defaultPassword")
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 2: Modify the DataStore after storing a file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 3: Modify the DataStore after initializing the user", func() {
			userlib.DebugMsg("Initializing user alice.")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Change every value in the map to defaultPassword.")
			for key, _ := range userlib.DatastoreGetMap() {
				userlib.DatastoreSet(key, []byte(defaultPassword))
			}

			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 4: Modify the DataStore before revoke invite.", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting another user session of alice")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone storing file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone creating invite for Bob.")
			bob_invite, err := alicePhone.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", bob_invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Clear DataStore.")
			userlib.DatastoreClear()

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 5: Modify the DataStore before accept invite.", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting another user session of alice")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone storing file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone creating invite for Bob.")
			bob_invite, err := alicePhone.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Clear DataStore.")
			userlib.DatastoreClear()

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", bob_invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 6: Modify the DataStore before accept invite.", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting another user session of alice")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone storing file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Clear DataStore.")
			userlib.DatastoreClear()

			userlib.DebugMsg("alicePhone creating invite for Bob.")
			_, err := alicePhone.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 7: Clear the DataStore before append file.", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting another user session of alice")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone storing file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Clear DataStore.")
			userlib.DatastoreClear()

			userlib.DebugMsg("alicePhone creating invite for Bob.")
			_, err := alicePhone.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Storage Test 8: Testing modify dataStore after accept invitation.", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second user session of Alice")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone storing file %s with content: %s", aliceFile, contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alicePhone creating invite for Bob.")
			invite, err := alicePhone.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreClear()

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 1: The client MUST enforce that there is only a single copy of a file.", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating file invitation for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting file invitation from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check if there is only a single copy of a file")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Sharing and Revocation Test 2: Accept the invitation after revoke", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentOne)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for bob.")
			bob_invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for charles.")
			charles_invitation, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revoke bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking if charles can accept the file invitaiton.")
			err = charles.AcceptInvitation("alice", charles_invitation, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking if bob can accept the invitaion or not")
			err = bob.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking if charles can load file")
			data, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Checking if charles can append to file")
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking the content of the file")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Sharing and Revocation Test 3: Accept the invitaion under same fileName or the invitaion for someone else", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file aliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob stores file bobFile.")
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice send file invitation to bob")
			bob_invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Unable to accept file invitation from alice under the fileName bobFile")
			err = bob.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Unable to accept the file invitaion from alice that doesn't belong to charles")
			err = charles.AcceptInvitation("alice", bob_invitation, charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 4: Change the value before accepting the invitaion", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file aliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Send file invitation to bob")
			bob_invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Randomly change the value in the DataStore.")

			for key, value := range userlib.DatastoreGetMap() {
				newValue := value
				if value[10] == byte(10) {
					newValue[10] = byte(32)
				} else {
					newValue[10] = byte(10)
				}
				userlib.DatastoreSet(key, newValue)
			}

			userlib.DebugMsg("Unable to accept invitation")
			err = bob.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 5: Send the invitation for the user does not exist", func() {
			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", alice, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			bob_invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting invite under name %s.", bobFile)
			err = bob.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 6: Share with three users and revoke everyone's access", func() {
			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users doris.")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", alice, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			bob_invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for charles for file %s.", aliceFile)
			charles_invitation, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for doris for file %s.", aliceFile)
			doris_invitation, err := alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revoke bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revoke charles's access")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revoke doris's access")
			err = alice.RevokeAccess(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite under name %s.", bobFile)
			err = bob.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles accepting invite under name %s.", charlesFile)
			err = charles.AcceptInvitation("alice", charles_invitation, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("doris accepting invite under name %s.", dorisFile)
			err = doris.AcceptInvitation("alice", doris_invitation, dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking if bob can load file")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking if charles can load file")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking if doris can load file")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 7: Change the location of invitation", func() {
			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", alice, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			bob_invitation_uuid, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Obtain the bob_invitation from dataStore")
			bob_invitation, _ := userlib.DatastoreGet(bob_invitation_uuid)

			new_uuid := uuid.New()
			userlib.DatastoreSet(new_uuid, bob_invitation)

			userlib.DebugMsg("Bob accepting invite under name %s.", bobFile)
			err = bob.AcceptInvitation("alice", new_uuid, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 8: Owner shouldn't be able to send invite or revoke to themself", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file aliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice send file invitation to Alice")
			invitaion, err := alice.CreateInvitation(aliceFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice accepting invite under name %s.", bobFile)
			err = alice.AcceptInvitation("alice", invitaion, bobFile)
			Expect(err).ToNot(BeNil())

			// userlib.DatastoreClear()

			userlib.DebugMsg("Alice revoke alice's access")
			err = alice.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking if alice can load file")
			_, err = alice.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 9: Revoke grandchild", func() {
			userlib.DebugMsg("Initializing users alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users doris.")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice stores file aliceFile.")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			bob_invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite under name %s.", bobFile)
			err = bob.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s.", bobFile)
			charles_invitation, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepting invite under name %s.", charlesFile)
			err = charles.AcceptInvitation("bob", charles_invitation, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoke bob's access")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			bob_invitation, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite under name %s.", bobFile)
			err = bob.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking if bob can load file")
			_, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking if charles can load file")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Sharing and Revocation Test 10: Test multi-session accept invitation", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing users bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentOne)
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice to alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob to bobPhone.")
			bobPhone, err := client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data using alicePhone: %s", contentOne)
			err = alicePhone.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s.", aliceFile)
			bob_invitation, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite under name %s.", bobFile)
			err = bobPhone.AcceptInvitation("alice", bob_invitation, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user bob to bobTablet.")
			bobTablet, err := client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file ...")
			data, err := bobTablet.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Efficiency Test 1: Append new content to previously stored files.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing aliceFile data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending aliceFile data: %s", contentOne)
			bandwidth1 := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Loading aliceFile...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(strings.Repeat(contentOne, 2))))

			userlib.DebugMsg("Storing aliceFile 1 data: 10000 * %s", contentOne)
			err = alice.StoreFile(aliceFile+"1", []byte(strings.Repeat(contentOne, 10000)))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending aliceFile 1 data: %s", contentOne)
			bandwidth2 := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile+"1", []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Loading aliceFile...")
			data, err = alice.LoadFile(aliceFile + "1")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(strings.Repeat(contentOne, 10001))))

			userlib.DebugMsg("The bandwidth of MUST NOT scale linearly with the size of file.")
			userlib.DebugMsg(" bandwidth 1: ", bandwidth1, "bandwidth 2: ", bandwidth2)
		})

		Specify("Efficiency Test 2: Append time shouldn't depend on number of previous appends.", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Append one time")
			bw1 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			})

			userlib.DebugMsg("Append 100 times")
			for i := 0; i < 100; i++ {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			}

			userlib.DebugMsg("Append one time")
			bw2 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			})

			userlib.DebugMsg("Check the speed")
			Expect(bw1).To(Equal(bw2))
		})

		Specify("Efficiency Test 3: Append shouldn't depend on size of previous append", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing aliceFile.")
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Append one time")
			bw1 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			})

			userlib.DebugMsg("Append a really long string")
			BigString := strings.Repeat(contentOne, 100000)
			alice.AppendToFile(aliceFile, []byte(BigString))

			userlib.DebugMsg("Append one time")
			bw2 := measureBandwidth(func() {
				alice.AppendToFile(aliceFile, []byte(contentOne))
			})

			userlib.DebugMsg("Check the speed")
			Expect(bw1).To(Equal(bw2))

			userlib.DebugMsg("Check the content of the file")
			Expect(alice.LoadFile(aliceFile)).To(Equal([]byte(strings.Repeat(contentOne, 100003))))
		})

		Specify("Efficiency Test 4: Append shouldn't depend on size of filename", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing aliceFile.")
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Storing a file with the long fileName.")
			longFileName := strings.Repeat(contentOne, 100000)
			alice.StoreFile(longFileName, []byte(contentOne))

			userlib.DebugMsg("Append to longFileName")
			bw2 := measureBandwidth(func() {
				alice.AppendToFile(longFileName, []byte(contentOne))
			})

			userlib.DebugMsg("Check the speed")
			okay := false
			if bw2 < 10000 {
				okay = true
			}
			Expect(okay).To(Equal(true))

			userlib.DebugMsg("Check the file content")
			Expect(alice.LoadFile(longFileName)).To(Equal([]byte(contentOne + contentOne)))
		})
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
})
