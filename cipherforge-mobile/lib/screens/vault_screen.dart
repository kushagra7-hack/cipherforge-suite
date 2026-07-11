// =============================================================================
// VaultScreen — Encrypted Password Vault Dashboard
// =============================================================================
//
// This screen displays the user's stored credentials and provides:
//
// 1. **Decrypted Title ListView**
//    - Uses ListView.builder for efficient rendering of large vaults.
//    - Each item shows the decrypted title and a timestamp.
//    - Decryption happens on-demand when items are loaded, using the
//      in-memory master key from SecureSessionManager.
//
// 2. **Bottom Sheet Credential Viewer**
//    - Tapping an item opens a bottom sheet with full credential details.
//    - Password is hidden by default with a toggle to reveal.
//    - Copy buttons for username, password, and URL.
//
// 3. **30-Second Clipboard Auto-Clear**
//    - When a password is copied to clipboard, a 30-second timer starts.
//    - After 30 seconds, the clipboard is automatically cleared.
//    - This prevents another app from reading the password from clipboard
//      after the user has pasted it.
//    - A snackbar shows the countdown.
//
// 4. **Add/Edit/Delete Operations**
//    - FAB to add new credentials.
//    - Edit and delete from the bottom sheet.
//    - All operations re-encrypt data with a fresh IV.
//
// SECURITY NOTES:
// - Passwords are decrypted on-demand and displayed only when the user
//   explicitly taps the reveal button.
// - The master key is never passed through widget constructors — it's
//   read from the SecureSessionManager Riverpod provider.
// - Clipboard is cleared after 30 seconds to prevent clipboard sniffing.
// =============================================================================

import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/security_engine.dart';
import '../data/vault_repository.dart';
import '../services/secure_session_manager.dart';
import 'security_audit_screen.dart';

/// The main vault dashboard screen.
///
/// Displays all stored credentials and provides CRUD operations.
/// Requires an active session with a valid master key in SecureSessionManager.
class VaultScreen extends ConsumerStatefulWidget {
  const VaultScreen({super.key});

  @override
  ConsumerState<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends ConsumerState<VaultScreen> {
  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  /// Repository for CRUD operations.
  final VaultRepository _repository = VaultRepository();

  /// List of decrypted vault items currently displayed.
  List<VaultItem> _items = [];

  /// Whether items are currently being loaded/decrypted.
  bool _isLoading = true;

  /// Timer for clipboard auto-clear.
  Timer? _clipboardTimer;

  /// Remaining seconds until clipboard is cleared.
  int _clipboardSecondsRemaining = 0;

  /// Search query for filtering items.
  String _searchQuery = '';

  /// CSPRNG for generating UUIDs.
  /// CRITICAL: Uses Random.secure(), NOT Random() or Math.random().
  static final Random _secureRandom = Random.secure();

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    // Load and decrypt all vault items on screen initialization.
    _loadItems();
  }

  @override
  void dispose() {
    _clipboardTimer?.cancel();
    super.dispose();
  }

  /// Loads and decrypts all vault items using the in-memory master key.
  Future<void> _loadItems() async {
    setState(() => _isLoading = true);

    try {
      final masterKey = ref.read(secureSessionManagerProvider);
      if (masterKey == null) {
        // Session expired or key was zeroed — navigate back to auth.
        if (mounted) {
          Navigator.of(context).pushReplacementNamed('/');
        }
        return;
      }

      final items = await _repository.getAllItems(masterKey);
      if (mounted) {
        setState(() {
          _items = items;
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isLoading = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error loading vault: $e')),
        );
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Clipboard Operations
  // ---------------------------------------------------------------------------

  /// Copies sensitive text to clipboard with a 30-second auto-clear timer.
  ///
  /// SECURITY: The clipboard is a shared resource — any app can read it.
  /// By clearing it after 30 seconds, we limit the exposure window.
  /// This is especially important on Android where clipboard history
  /// managers may persist clipboard contents.
  ///
  /// [text] — The sensitive text to copy (e.g., a password).
  /// [label] — A human-readable label for the snackbar (e.g., "Password").
  void _copyToClipboardWithAutoClear(String text, String label) {
    // Copy to clipboard.
    Clipboard.setData(ClipboardData(text: text));

    // Cancel any existing clipboard timer.
    _clipboardTimer?.cancel();

    // Start 30-second countdown.
    _clipboardSecondsRemaining = 30;

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$label copied. Clipboard will clear in 30s.'),
        duration: const Duration(seconds: 3),
        behavior: SnackBarBehavior.floating,
      ),
    );

    _clipboardTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
      _clipboardSecondsRemaining--;
      if (_clipboardSecondsRemaining <= 0) {
        timer.cancel();
        // Clear the clipboard by setting it to empty.
        Clipboard.setData(const ClipboardData(text: ''));
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Clipboard cleared for security.'),
              duration: Duration(seconds: 2),
              behavior: SnackBarBehavior.floating,
            ),
          );
        }
      }
    });
  }

  // ---------------------------------------------------------------------------
  // CRUD Operations
  // ---------------------------------------------------------------------------

  /// Generates a UUID v4 using CSPRNG.
  ///
  /// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
  /// The '4' indicates UUID version 4 (random).
  /// CRITICAL: Uses Random.secure() for all random bytes.
  String _generateUuid() {
    final bytes = List.generate(16, (_) => _secureRandom.nextInt(256));

    // Set version (4) and variant (10xx) bits per RFC 4122.
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // Variant 1

    final hex = bytes
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();

    return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-'
        '${hex.substring(12, 16)}-${hex.substring(16, 20)}-'
        '${hex.substring(20)}';
  }

  /// Shows a dialog to add a new credential.
  Future<void> _showAddItemDialog() async {
    final titleController = TextEditingController();
    final usernameController = TextEditingController();
    final passwordController = TextEditingController();
    final urlController = TextEditingController();
    final notesController = TextEditingController();

    final result = await showDialog<bool>(
      context: context,
      builder: (context) => _AddEditDialog(
        title: 'Add Credential',
        titleController: titleController,
        usernameController: usernameController,
        passwordController: passwordController,
        urlController: urlController,
        notesController: notesController,
      ),
    );

    if (result == true) {
      final masterKey = ref.read(secureSessionManagerProvider);
      if (masterKey == null) return;

      final now = DateTime.now();
      final item = VaultItem(
        id: _generateUuid(),
        title: titleController.text,
        username: usernameController.text,
        password: passwordController.text,
        url: urlController.text,
        notes: notesController.text,
        createdAt: now,
        updatedAt: now,
      );

      await _repository.insertItem(item, masterKey);
      await _loadItems();
    }

    // Clear controllers to remove sensitive data from memory.
    titleController.dispose();
    usernameController.dispose();
    passwordController.dispose();
    urlController.dispose();
    notesController.dispose();
  }

  /// Shows a dialog to edit an existing credential.
  Future<void> _showEditItemDialog(VaultItem item) async {
    final titleController = TextEditingController(text: item.title);
    final usernameController = TextEditingController(text: item.username);
    final passwordController = TextEditingController(text: item.password);
    final urlController = TextEditingController(text: item.url);
    final notesController = TextEditingController(text: item.notes);

    final result = await showDialog<bool>(
      context: context,
      builder: (context) => _AddEditDialog(
        title: 'Edit Credential',
        titleController: titleController,
        usernameController: usernameController,
        passwordController: passwordController,
        urlController: urlController,
        notesController: notesController,
      ),
    );

    if (result == true) {
      final masterKey = ref.read(secureSessionManagerProvider);
      if (masterKey == null) return;

      final updatedItem = VaultItem(
        id: item.id,
        title: titleController.text,
        username: usernameController.text,
        password: passwordController.text,
        url: urlController.text,
        notes: notesController.text,
        createdAt: item.createdAt,
        updatedAt: DateTime.now(),
      );

      await _repository.updateItem(updatedItem, masterKey);
      await _loadItems();
    }

    titleController.dispose();
    usernameController.dispose();
    passwordController.dispose();
    urlController.dispose();
    notesController.dispose();
  }

  /// Deletes a vault item with confirmation.
  Future<void> _deleteItem(VaultItem item) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF161B22),
        title: const Text('Delete Credential',
            style: TextStyle(color: Colors.white)),
        content: Text(
          'Are you sure you want to delete "${item.title}"?\nThis action cannot be undone.',
          style: const TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true) {
      await _repository.deleteItem(item.id);
      await _loadItems();
      if (mounted) {
        Navigator.of(context).pop(); // Close the bottom sheet
      }
    }
  }

  /// Shows the credential details bottom sheet.
  void _showCredentialBottomSheet(VaultItem item) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: const Color(0xFF161B22),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (context) => _CredentialBottomSheet(
        item: item,
        onCopy: _copyToClipboardWithAutoClear,
        onEdit: () {
          Navigator.of(context).pop();
          _showEditItemDialog(item);
        },
        onDelete: () => _deleteItem(item),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // UI
  // ---------------------------------------------------------------------------

  /// Filters items based on the search query.
  List<VaultItem> get _filteredItems {
    if (_searchQuery.isEmpty) return _items;
    final query = _searchQuery.toLowerCase();
    return _items
        .where((item) =>
            item.title.toLowerCase().contains(query) ||
            item.username.toLowerCase().contains(query) ||
            item.url.toLowerCase().contains(query))
        .toList();
  }

  @override
  Widget build(BuildContext context) {
    // Watch the session state — if the key is zeroed, go back to auth.
    final masterKey = ref.watch(secureSessionManagerProvider);
    if (masterKey == null) {
      // Session expired — will navigate on next frame.
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          Navigator.of(context).pushReplacementNamed('/');
        }
      });
    }

    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: const Text(
          'Vault',
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
        actions: [
          // Security Audit button
          IconButton(
            icon: const Icon(Icons.shield_outlined, color: Colors.white70),
            tooltip: 'Security Audit',
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => SecurityAuditScreen(items: _items),
                ),
              );
            },
          ),
          // Lock button — zeroes the master key and returns to auth.
          IconButton(
            icon: const Icon(Icons.lock_outline, color: Colors.white70),
            tooltip: 'Lock Vault',
            onPressed: () {
              ref
                  .read(secureSessionManagerProvider.notifier)
                  .clearMasterKey();
              Navigator.of(context).pushReplacementNamed('/');
            },
          ),
        ],
      ),

      // ----- Search Bar -----
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: TextField(
              onChanged: (value) => setState(() => _searchQuery = value),
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                hintText: 'Search credentials...',
                hintStyle: const TextStyle(color: Colors.white30),
                prefixIcon: const Icon(Icons.search, color: Colors.white38),
                filled: true,
                fillColor: const Color(0xFF161B22),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide.none,
                ),
                contentPadding: const EdgeInsets.symmetric(vertical: 12),
              ),
            ),
          ),

          // ----- Item Count -----
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16.0),
            child: Row(
              children: [
                Text(
                  '${_filteredItems.length} credential${_filteredItems.length != 1 ? 's' : ''}',
                  style: const TextStyle(color: Colors.white38, fontSize: 13),
                ),
                const Spacer(),
              ],
            ),
          ),
          const SizedBox(height: 8),

          // ----- Item List -----
          Expanded(
            child: _isLoading
                ? const Center(
                    child: CircularProgressIndicator(
                      color: Color(0xFF1A73E8),
                    ),
                  )
                : _filteredItems.isEmpty
                    ? _buildEmptyState()
                    : ListView.builder(
                        itemCount: _filteredItems.length,
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        itemBuilder: (context, index) {
                          final item = _filteredItems[index];
                          return _buildItemCard(item);
                        },
                      ),
          ),
        ],
      ),

      // ----- FAB: Add Credential -----
      floatingActionButton: FloatingActionButton(
        onPressed: _showAddItemDialog,
        backgroundColor: const Color(0xFF1A73E8),
        child: const Icon(Icons.add, color: Colors.white),
      ),
    );
  }

  /// Builds the empty state widget when no items exist.
  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.lock_outlined,
            size: 64,
            color: Colors.white.withOpacity(0.15),
          ),
          const SizedBox(height: 16),
          Text(
            'No credentials stored yet',
            style: TextStyle(
              color: Colors.white.withOpacity(0.4),
              fontSize: 16,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Tap + to add your first credential',
            style: TextStyle(
              color: Colors.white.withOpacity(0.25),
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }

  /// Builds a card for a single vault item in the list.
  Widget _buildItemCard(VaultItem item) {
    // Get the first letter for the avatar.
    final initial = item.title.isNotEmpty ? item.title[0].toUpperCase() : '?';

    return Card(
      color: const Color(0xFF161B22),
      margin: const EdgeInsets.only(bottom: 8),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: ListTile(
        onTap: () => _showCredentialBottomSheet(item),
        leading: CircleAvatar(
          backgroundColor: const Color(0xFF1A73E8).withOpacity(0.2),
          child: Text(
            initial,
            style: const TextStyle(
              color: Color(0xFF1A73E8),
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        title: Text(
          item.title,
          style: const TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.w500,
          ),
        ),
        subtitle: Text(
          item.username,
          style: const TextStyle(color: Colors.white38, fontSize: 13),
        ),
        trailing: const Icon(
          Icons.chevron_right,
          color: Colors.white24,
        ),
      ),
    );
  }
}

// =============================================================================
// CREDENTIAL BOTTOM SHEET
// =============================================================================

/// Bottom sheet displaying full credential details.
///
/// The password is hidden by default and can be toggled with an eye icon.
/// Copy buttons trigger the 30-second clipboard auto-clear.
class _CredentialBottomSheet extends StatefulWidget {
  final VaultItem item;
  final void Function(String text, String label) onCopy;
  final VoidCallback onEdit;
  final VoidCallback onDelete;

  const _CredentialBottomSheet({
    required this.item,
    required this.onCopy,
    required this.onEdit,
    required this.onDelete,
  });

  @override
  State<_CredentialBottomSheet> createState() => _CredentialBottomSheetState();
}

class _CredentialBottomSheetState extends State<_CredentialBottomSheet> {
  /// Whether the password is currently visible.
  bool _passwordVisible = false;

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.55,
      minChildSize: 0.3,
      maxChildSize: 0.85,
      expand: false,
      builder: (context, scrollController) => SingleChildScrollView(
        controller: scrollController,
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ----- Handle -----
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 20),

            // ----- Title -----
            Text(
              widget.item.title,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 22,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 24),

            // ----- Username -----
            _buildField(
              label: 'Username',
              value: widget.item.username,
              icon: Icons.person_outline,
              onCopy: () =>
                  widget.onCopy(widget.item.username, 'Username'),
            ),
            const SizedBox(height: 16),

            // ----- Password -----
            _buildField(
              label: 'Password',
              value: _passwordVisible
                  ? widget.item.password
                  : '•' * widget.item.password.length.clamp(8, 20),
              icon: Icons.lock_outline,
              onCopy: () =>
                  widget.onCopy(widget.item.password, 'Password'),
              trailing: IconButton(
                icon: Icon(
                  _passwordVisible
                      ? Icons.visibility_off
                      : Icons.visibility,
                  color: Colors.white38,
                  size: 20,
                ),
                onPressed: () =>
                    setState(() => _passwordVisible = !_passwordVisible),
              ),
            ),
            const SizedBox(height: 16),

            // ----- URL -----
            if (widget.item.url.isNotEmpty)
              _buildField(
                label: 'URL',
                value: widget.item.url,
                icon: Icons.link,
                onCopy: () => widget.onCopy(widget.item.url, 'URL'),
              ),
            if (widget.item.url.isNotEmpty) const SizedBox(height: 16),

            // ----- Notes -----
            if (widget.item.notes.isNotEmpty) ...[
              const Text(
                'Notes',
                style: TextStyle(color: Colors.white38, fontSize: 12),
              ),
              const SizedBox(height: 4),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF0D1117),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text(
                  widget.item.notes,
                  style: const TextStyle(color: Colors.white70, fontSize: 14),
                ),
              ),
              const SizedBox(height: 16),
            ],

            // ----- Timestamps -----
            Text(
              'Created: ${_formatDate(widget.item.createdAt)}',
              style: const TextStyle(color: Colors.white24, fontSize: 11),
            ),
            Text(
              'Updated: ${_formatDate(widget.item.updatedAt)}',
              style: const TextStyle(color: Colors.white24, fontSize: 11),
            ),
            const SizedBox(height: 24),

            // ----- Action Buttons -----
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: widget.onEdit,
                    icon: const Icon(Icons.edit_outlined, size: 18),
                    label: const Text('Edit'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: const Color(0xFF1A73E8),
                      side: const BorderSide(color: Color(0xFF1A73E8)),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                      padding: const EdgeInsets.symmetric(vertical: 12),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: widget.onDelete,
                    icon: const Icon(Icons.delete_outline, size: 18),
                    label: const Text('Delete'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Colors.red,
                      side: const BorderSide(color: Colors.red),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                      ),
                      padding: const EdgeInsets.symmetric(vertical: 12),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  /// Builds a read-only field with a copy button.
  Widget _buildField({
    required String label,
    required String value,
    required IconData icon,
    required VoidCallback onCopy,
    Widget? trailing,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(color: Colors.white38, fontSize: 12),
        ),
        const SizedBox(height: 4),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: const Color(0xFF0D1117),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Row(
            children: [
              Icon(icon, color: Colors.white24, size: 18),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  value,
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 14,
                    fontFamily: 'monospace',
                  ),
                ),
              ),
              if (trailing != null) trailing,
              IconButton(
                icon: const Icon(Icons.copy, color: Colors.white38, size: 18),
                onPressed: onCopy,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            ],
          ),
        ),
      ],
    );
  }

  /// Formats a DateTime for display.
  String _formatDate(DateTime date) {
    return '${date.year}-${date.month.toString().padLeft(2, '0')}-'
        '${date.day.toString().padLeft(2, '0')} '
        '${date.hour.toString().padLeft(2, '0')}:'
        '${date.minute.toString().padLeft(2, '0')}';
  }
}

// =============================================================================
// ADD/EDIT DIALOG
// =============================================================================

/// Dialog for adding or editing a credential.
///
/// Includes a password generator button that creates a cryptographically
/// secure random password using [SecurityEngine.generatePassword].
class _AddEditDialog extends StatefulWidget {
  final String title;
  final TextEditingController titleController;
  final TextEditingController usernameController;
  final TextEditingController passwordController;
  final TextEditingController urlController;
  final TextEditingController notesController;

  const _AddEditDialog({
    required this.title,
    required this.titleController,
    required this.usernameController,
    required this.passwordController,
    required this.urlController,
    required this.notesController,
  });

  @override
  State<_AddEditDialog> createState() => _AddEditDialogState();
}

class _AddEditDialogState extends State<_AddEditDialog> {
  bool _showPassword = false;

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF161B22),
      title: Text(
        widget.title,
        style: const TextStyle(color: Colors.white),
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            _buildDialogField(widget.titleController, 'Title', Icons.label),
            const SizedBox(height: 12),
            _buildDialogField(
                widget.usernameController, 'Username', Icons.person),
            const SizedBox(height: 12),

            // Password field with generator button.
            TextField(
              controller: widget.passwordController,
              obscureText: !_showPassword,
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                labelText: 'Password',
                labelStyle: const TextStyle(color: Colors.white54),
                prefixIcon: const Icon(Icons.lock, color: Colors.white38),
                suffixIcon: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Toggle password visibility.
                    IconButton(
                      icon: Icon(
                        _showPassword
                            ? Icons.visibility_off
                            : Icons.visibility,
                        color: Colors.white38,
                        size: 20,
                      ),
                      onPressed: () =>
                          setState(() => _showPassword = !_showPassword),
                    ),
                    // Generate secure password.
                    IconButton(
                      icon: const Icon(Icons.auto_awesome,
                          color: Color(0xFF1A73E8), size: 20),
                      tooltip: 'Generate secure password',
                      onPressed: () {
                        final password =
                            SecurityEngine.generatePassword(length: 20);
                        widget.passwordController.text = password;
                        setState(() => _showPassword = true);
                      },
                    ),
                  ],
                ),
                filled: true,
                fillColor: const Color(0xFF0D1117),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide.none,
                ),
              ),
            ),
            const SizedBox(height: 12),
            _buildDialogField(widget.urlController, 'URL', Icons.link),
            const SizedBox(height: 12),
            _buildDialogField(widget.notesController, 'Notes', Icons.note,
                maxLines: 3),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () {
            if (widget.titleController.text.isEmpty) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Title is required')),
              );
              return;
            }
            Navigator.of(context).pop(true);
          },
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF1A73E8),
          ),
          child: const Text('Save', style: TextStyle(color: Colors.white)),
        ),
      ],
    );
  }

  Widget _buildDialogField(
    TextEditingController controller,
    String label,
    IconData icon, {
    int maxLines = 1,
  }) {
    return TextField(
      controller: controller,
      maxLines: maxLines,
      style: const TextStyle(color: Colors.white),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: const TextStyle(color: Colors.white54),
        prefixIcon: Icon(icon, color: Colors.white38),
        filled: true,
        fillColor: const Color(0xFF0D1117),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide.none,
        ),
      ),
    );
  }
}
