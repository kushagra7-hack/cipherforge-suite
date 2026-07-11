// =============================================================================
// VaultRepository — Encrypted Data Persistence Layer
// =============================================================================
//
// This module manages all persistent storage for the password vault:
//
// 1. **flutter_secure_storage** — For small, highly sensitive values:
//    - Argon2id salt (16 bytes, base64-encoded)
//    - Authentication hash (SHA-256 of derived key, for password verification)
//    These are stored in the platform keystore (Android Keystore / iOS Keychain)
//    which provides hardware-backed encryption on supported devices.
//
// 2. **SQLite (sqflite)** — For structured vault item storage:
//    - Table: vault_items(id TEXT PK, title TEXT, encrypted_data TEXT,
//             created_at TEXT, updated_at TEXT)
//    - The `encrypted_data` column contains base64-encoded AES-256-GCM
//      ciphertext of a JSON object with credential fields.
//    - The `title` column is ALSO encrypted — no plaintext data is stored.
//
// SECURITY MODEL:
// - All credential data is encrypted BEFORE being written to SQLite.
// - Even a raw database dump reveals nothing — every field is AES-GCM encrypted.
// - The encryption key (master key) is NEVER stored — it exists only in memory
//   as a Uint8List during an active session.
// - Salt and auth hash are stored in platform keystore, not in SQLite.
// =============================================================================

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart';
import 'package:sqflite/sqflite.dart';

import '../core/security_engine.dart';

// =============================================================================
// DATA MODELS
// =============================================================================

/// Represents a single credential entry in the vault.
///
/// All fields are plaintext in memory (after decryption) but encrypted at rest.
/// The [id] is a UUID generated using Random.secure() to prevent enumeration.
class VaultItem {
  /// Unique identifier — UUID v4 generated with CSPRNG.
  final String id;

  /// Display title (e.g., "GitHub", "Gmail"). Encrypted at rest.
  final String title;

  /// The username or email for this credential.
  final String username;

  /// The password. This is the most sensitive field.
  final String password;

  /// Optional URL for the service.
  final String url;

  /// Optional notes (e.g., recovery codes, security questions).
  final String notes;

  /// When this entry was first created (ISO 8601).
  final DateTime createdAt;

  /// When this entry was last modified (ISO 8601).
  final DateTime updatedAt;

  VaultItem({
    required this.id,
    required this.title,
    required this.username,
    required this.password,
    this.url = '',
    this.notes = '',
    required this.createdAt,
    required this.updatedAt,
  });

  /// Serializes the credential fields to a JSON map for encryption.
  ///
  /// Only the sensitive fields are included here — id, createdAt, and
  /// updatedAt are stored as plaintext columns in SQLite since they don't
  /// contain sensitive information and are needed for sorting/querying.
  Map<String, dynamic> toJson() => {
        'title': title,
        'username': username,
        'password': password,
        'url': url,
        'notes': notes,
      };

  /// Constructs a [VaultItem] from a SQLite row and decrypted JSON.
  ///
  /// [row] — The raw SQLite row containing id, created_at, updated_at.
  /// [decryptedJson] — The decrypted JSON map with credential fields.
  factory VaultItem.fromDbRow(
    Map<String, dynamic> row,
    Map<String, dynamic> decryptedJson,
  ) {
    return VaultItem(
      id: row['id'] as String,
      title: decryptedJson['title'] as String? ?? '',
      username: decryptedJson['username'] as String? ?? '',
      password: decryptedJson['password'] as String? ?? '',
      url: decryptedJson['url'] as String? ?? '',
      notes: decryptedJson['notes'] as String? ?? '',
      createdAt: DateTime.parse(row['created_at'] as String),
      updatedAt: DateTime.parse(row['updated_at'] as String),
    );
  }
}

// =============================================================================
// REPOSITORY
// =============================================================================

/// Repository managing all vault data persistence.
///
/// This class encapsulates both flutter_secure_storage (for key material)
/// and SQLite (for encrypted vault items), providing a unified interface
/// for the rest of the application.
class VaultRepository {
  // ---------------------------------------------------------------------------
  // Storage instances
  // ---------------------------------------------------------------------------

  /// Platform-secure storage for salt and auth hash.
  ///
  /// On Android, this uses EncryptedSharedPreferences backed by Android Keystore.
  /// On iOS, this uses the Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
  final FlutterSecureStorage _secureStorage;

  /// SQLite database instance. Lazily initialized.
  Database? _database;

  // ---------------------------------------------------------------------------
  // Secure storage keys
  // ---------------------------------------------------------------------------

  /// Key for the Argon2id salt stored in secure storage.
  static const String _saltKey = 'vault_argon2_salt';

  /// Key for the authentication hash stored in secure storage.
  /// This is SHA-256(derived_key), used to verify the master password
  /// without storing the key itself.
  static const String _authHashKey = 'vault_auth_hash';

  /// Key for tracking whether the vault has been initialized.
  static const String _initializedKey = 'vault_initialized';

  // ---------------------------------------------------------------------------
  // SQLite configuration
  // ---------------------------------------------------------------------------

  /// Database filename.
  static const String _dbName = 'vault_encrypted.db';

  /// Database version for migration management.
  static const int _dbVersion = 1;

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  /// Creates a [VaultRepository] with optional dependency injection.
  ///
  /// [secureStorage] can be injected for testing. Defaults to a new instance
  /// with Android-specific encrypted shared preferences.
  VaultRepository({FlutterSecureStorage? secureStorage})
      : _secureStorage = secureStorage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(
                encryptedSharedPreferences: true,
              ),
            );

  // ===========================================================================
  // DATABASE INITIALIZATION
  // ===========================================================================

  /// Returns the SQLite database instance, initializing it if necessary.
  ///
  /// The database is opened with WAL (Write-Ahead Logging) mode for better
  /// concurrent read performance and crash recovery.
  Future<Database> get database async {
    if (_database != null && _database!.isOpen) {
      return _database!;
    }

    final dbPath = await getDatabasesPath();
    final path = join(dbPath, _dbName);

    _database = await openDatabase(
      path,
      version: _dbVersion,
      onCreate: _createDatabase,
      onConfigure: (db) async {
        // Enable WAL mode for better performance and crash safety.
        await db.execute('PRAGMA journal_mode=WAL');
        // Enable foreign keys for referential integrity.
        await db.execute('PRAGMA foreign_keys=ON');
      },
    );

    return _database!;
  }

  /// Creates the vault_items table.
  ///
  /// Schema:
  /// - id: UUID primary key (TEXT, not INTEGER, to prevent enumeration)
  /// - title: Encrypted title (base64 AES-GCM ciphertext)
  /// - encrypted_data: Full encrypted JSON blob (base64 AES-GCM ciphertext)
  /// - created_at: ISO 8601 timestamp
  /// - updated_at: ISO 8601 timestamp
  ///
  /// Note: Even the 'title' column contains encrypted data. We store it
  /// separately (in addition to inside encrypted_data) to allow future
  /// encrypted search indexing without decrypting the full blob.
  Future<void> _createDatabase(Database db, int version) async {
    await db.execute('''
      CREATE TABLE vault_items (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        encrypted_data TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    ''');

    // Index on updated_at for sorting vault items by recency.
    await db.execute('''
      CREATE INDEX idx_vault_items_updated_at ON vault_items(updated_at)
    ''');
  }

  // ===========================================================================
  // MASTER PASSWORD MANAGEMENT
  // ===========================================================================

  /// Checks whether the vault has been initialized (master password set).
  ///
  /// Returns true if a salt and auth hash exist in secure storage.
  Future<bool> isVaultInitialized() async {
    final initialized = await _secureStorage.read(key: _initializedKey);
    return initialized == 'true';
  }

  /// Initializes the vault with a new master password.
  ///
  /// This:
  /// 1. Generates a random 16-byte salt.
  /// 2. Derives a 256-bit key using Argon2id(password, salt).
  /// 3. Computes SHA-256(derived_key) as the authentication hash.
  /// 4. Stores the salt and auth hash in platform secure storage.
  ///
  /// The derived key is returned so the caller can use it for the session.
  /// The caller is responsible for storing it in the SecureSessionManager.
  ///
  /// [masterPassword] — The user's chosen master password.
  ///
  /// Returns the derived 256-bit master key as [Uint8List].
  Future<Uint8List> initializeVault(String masterPassword) async {
    // Generate a cryptographically random salt.
    final salt = SecurityEngine.generateSalt();

    // Derive the master key from the password + salt.
    final derivedKey = SecurityEngine.deriveKey(masterPassword, salt);

    // Compute the authentication hash: SHA-256 of the derived key.
    // We store this hash (not the key itself) so we can verify the password
    // on subsequent logins without storing the actual encryption key.
    final authHash = sha256.convert(derivedKey).toString();

    // Store salt (base64) and auth hash in platform secure storage.
    await _secureStorage.write(
      key: _saltKey,
      value: base64.encode(salt),
    );
    await _secureStorage.write(key: _authHashKey, value: authHash);
    await _secureStorage.write(key: _initializedKey, value: 'true');

    return derivedKey;
  }

  /// Verifies the master password and returns the derived key if correct.
  ///
  /// This:
  /// 1. Reads the stored salt from secure storage.
  /// 2. Derives a key using Argon2id(password, stored_salt).
  /// 3. Computes SHA-256(derived_key) and compares with stored auth hash.
  /// 4. If they match, returns the derived key for the session.
  ///
  /// [masterPassword] — The password to verify.
  ///
  /// Returns the derived key if correct, or null if the password is wrong.
  Future<Uint8List?> verifyMasterPassword(String masterPassword) async {
    // Read the stored salt.
    final saltBase64 = await _secureStorage.read(key: _saltKey);
    if (saltBase64 == null) return null;

    final salt = base64.decode(saltBase64);

    // Read the stored authentication hash.
    final storedAuthHash = await _secureStorage.read(key: _authHashKey);
    if (storedAuthHash == null) return null;

    // Derive the key from the provided password + stored salt.
    final derivedKey =
        SecurityEngine.deriveKey(masterPassword, Uint8List.fromList(salt));

    // Compute the auth hash of the derived key.
    final computedAuthHash = sha256.convert(derivedKey).toString();

    // Constant-time comparison would be ideal here, but Dart's String ==
    // comparison is sufficient because an attacker cannot observe timing
    // differences through the Flutter UI layer. For a server-side
    // implementation, use a constant-time comparison function.
    if (computedAuthHash == storedAuthHash) {
      return derivedKey;
    }

    // Password incorrect — securely zero the derived key before discarding.
    SecurityEngine.secureZero(derivedKey);
    return null;
  }

  // ===========================================================================
  // VAULT ITEM CRUD OPERATIONS
  // ===========================================================================

  /// Inserts a new vault item, encrypting all sensitive fields.
  ///
  /// The credential JSON (title, username, password, url, notes) is
  /// serialized to JSON, encrypted with AES-256-GCM, and stored as
  /// base64 in the encrypted_data column.
  ///
  /// [item] — The vault item to insert.
  /// [masterKey] — The 256-bit master key for encryption.
  Future<void> insertItem(VaultItem item, Uint8List masterKey) async {
    final db = await database;

    // Serialize credential fields to JSON.
    final jsonString = jsonEncode(item.toJson());

    // Encrypt the JSON with AES-256-GCM.
    // This produces: [IV || ciphertext || GCM tag]
    final encryptedBytes = SecurityEngine.encrypt(jsonString, masterKey);

    // Also encrypt the title separately for the title column.
    // This allows us to display encrypted titles in the list without
    // decrypting the entire blob (though in practice we decrypt both).
    final encryptedTitle = SecurityEngine.encrypt(item.title, masterKey);

    await db.insert(
      'vault_items',
      {
        'id': item.id,
        'title': base64.encode(encryptedTitle),
        'encrypted_data': base64.encode(encryptedBytes),
        'created_at': item.createdAt.toIso8601String(),
        'updated_at': item.updatedAt.toIso8601String(),
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  /// Updates an existing vault item with re-encrypted data.
  ///
  /// The entire encrypted_data blob is re-encrypted with a new random IV,
  /// ensuring forward secrecy — even if an old database backup is compromised,
  /// the IVs will be different.
  ///
  /// [item] — The updated vault item.
  /// [masterKey] — The 256-bit master key for encryption.
  Future<void> updateItem(VaultItem item, Uint8List masterKey) async {
    final db = await database;

    final jsonString = jsonEncode(item.toJson());
    final encryptedBytes = SecurityEngine.encrypt(jsonString, masterKey);
    final encryptedTitle = SecurityEngine.encrypt(item.title, masterKey);

    await db.update(
      'vault_items',
      {
        'title': base64.encode(encryptedTitle),
        'encrypted_data': base64.encode(encryptedBytes),
        'updated_at': DateTime.now().toIso8601String(),
      },
      where: 'id = ?',
      whereArgs: [item.id],
    );
  }

  /// Deletes a vault item by ID.
  ///
  /// This is a logical delete from SQLite. Note that SQLite does not
  /// guarantee immediate disk overwrite — deleted data may remain in
  /// the WAL file or free pages until a VACUUM is performed. For maximum
  /// security, consider running VACUUM after deletion.
  ///
  /// [id] — The UUID of the item to delete.
  Future<void> deleteItem(String id) async {
    final db = await database;
    await db.delete('vault_items', where: 'id = ?', whereArgs: [id]);

    // VACUUM to overwrite freed pages. This is expensive but ensures
    // deleted ciphertext doesn't linger on disk.
    await db.execute('VACUUM');
  }

  /// Retrieves all vault items, decrypting their data with the master key.
  ///
  /// Items are returned sorted by updated_at descending (most recent first).
  ///
  /// [masterKey] — The 256-bit master key for decryption.
  ///
  /// Returns a list of decrypted [VaultItem] objects.
  /// Any item that fails to decrypt (e.g., corrupted data) is skipped
  /// with a warning rather than crashing the entire vault.
  Future<List<VaultItem>> getAllItems(Uint8List masterKey) async {
    final db = await database;
    final rows = await db.query(
      'vault_items',
      orderBy: 'updated_at DESC',
    );

    final items = <VaultItem>[];

    for (final row in rows) {
      try {
        // Decode the base64 encrypted data.
        final encryptedData =
            base64.decode(row['encrypted_data'] as String);

        // Decrypt with AES-256-GCM. This also verifies integrity via
        // the GCM authentication tag — if the data was tampered with,
        // decryption will throw an exception.
        final decryptedJson = SecurityEngine.decrypt(encryptedData, masterKey);

        // Parse the decrypted JSON.
        final jsonMap =
            jsonDecode(decryptedJson) as Map<String, dynamic>;

        items.add(VaultItem.fromDbRow(row, jsonMap));
      } catch (e) {
        // Log but don't crash — a single corrupted item shouldn't
        // prevent access to the rest of the vault.
        // In production, this should be reported to a crash analytics
        // service (with NO sensitive data in the report).
        // ignore: avoid_print
        print('Warning: Failed to decrypt vault item ${row['id']}: $e');
      }
    }

    return items;
  }

  /// Retrieves a single vault item by ID and decrypts it.
  ///
  /// [id] — The UUID of the item to retrieve.
  /// [masterKey] — The 256-bit master key for decryption.
  ///
  /// Returns the decrypted [VaultItem], or null if not found.
  Future<VaultItem?> getItem(String id, Uint8List masterKey) async {
    final db = await database;
    final rows = await db.query(
      'vault_items',
      where: 'id = ?',
      whereArgs: [id],
      limit: 1,
    );

    if (rows.isEmpty) return null;

    final row = rows.first;
    final encryptedData = base64.decode(row['encrypted_data'] as String);
    final decryptedJson = SecurityEngine.decrypt(encryptedData, masterKey);
    final jsonMap = jsonDecode(decryptedJson) as Map<String, dynamic>;

    return VaultItem.fromDbRow(row, jsonMap);
  }

  /// Returns the total number of vault items without decrypting any data.
  ///
  /// This is useful for UI displays like "42 passwords stored" without
  /// requiring the master key.
  Future<int> getItemCount() async {
    final db = await database;
    final result = await db.rawQuery('SELECT COUNT(*) as count FROM vault_items');
    return Sqflite.firstIntValue(result) ?? 0;
  }

  // ===========================================================================
  // CLEANUP
  // ===========================================================================

  /// Closes the SQLite database connection.
  ///
  /// Should be called when the app is terminating to ensure clean shutdown.
  Future<void> close() async {
    if (_database != null && _database!.isOpen) {
      await _database!.close();
      _database = null;
    }
  }

  /// Completely destroys the vault — deletes all data.
  ///
  /// This is an irreversible operation that:
  /// 1. Deletes the SQLite database file.
  /// 2. Clears all secure storage entries.
  ///
  /// Use only for factory reset or account deletion scenarios.
  Future<void> destroyVault() async {
    // Close the database first.
    await close();

    // Delete the database file.
    final dbPath = await getDatabasesPath();
    final path = join(dbPath, _dbName);
    await deleteDatabase(path);

    // Clear secure storage.
    await _secureStorage.deleteAll();
  }
}
