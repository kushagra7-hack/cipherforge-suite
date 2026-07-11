// =============================================================================
// SecurityAuditScreen — Password Health Analysis Dashboard
// =============================================================================
//
// This screen provides a comprehensive security audit of all stored passwords:
//
// 1. **Reused Password Detection**
//    - Identifies passwords that are used across multiple entries.
//    - Password reuse is one of the most common security mistakes — if one
//      service is breached, all accounts sharing that password are compromised.
//
// 2. **Weak Password Detection**
//    - Uses Shannon entropy to classify password strength.
//    - Weak: < 50 bits (vulnerable to offline brute force)
//    - Good: 50-70 bits (adequate for most purposes)
//    - Excellent: > 70 bits (resistant to all known attacks)
//
// 3. **Breached Password Detection (k-Anonymity)**
//    - Checks passwords against the Have I Been Pwned (HIBP) API.
//    - Uses k-Anonymity: only the first 5 characters of the SHA-1 hash
//      are sent to the API, so the full hash (and thus the password) is
//      never transmitted.
//    - Batch processing to avoid overwhelming the API.
//
// 4. **fl_chart Pie Charts**
//    - Visual breakdown of password health across the vault.
//    - Color-coded sections: Red (weak/breached), Orange (reused), Green (good).
//
// SECURITY NOTES:
// - Passwords are analyzed in memory — no plaintext is ever sent to any API.
// - k-Anonymity ensures the HIBP API cannot determine which password we're
//   checking, even if they log all requests.
// - Analysis results are ephemeral — not stored to disk.
// =============================================================================

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../core/security_engine.dart';
import '../data/vault_repository.dart';

/// Security audit dashboard for analyzing password health.
///
/// Receives the list of already-decrypted [VaultItem]s from the vault screen.
/// All analysis happens in memory — no data is persisted.
class SecurityAuditScreen extends StatefulWidget {
  /// The decrypted vault items to analyze.
  final List<VaultItem> items;

  const SecurityAuditScreen({super.key, required this.items});

  @override
  State<SecurityAuditScreen> createState() => _SecurityAuditScreenState();
}

class _SecurityAuditScreenState extends State<SecurityAuditScreen> {
  // ---------------------------------------------------------------------------
  // Analysis results
  // ---------------------------------------------------------------------------

  /// Items with weak passwords (< 50 bits entropy).
  List<_AuditResult> _weakPasswords = [];

  /// Items with reused passwords (same password on multiple entries).
  List<_AuditResult> _reusedPasswords = [];

  /// Items with passwords found in known data breaches.
  List<_AuditResult> _breachedPasswords = [];

  /// Items with good password health.
  List<_AuditResult> _healthyPasswords = [];

  /// Whether the breach check is currently running.
  bool _isCheckingBreaches = false;

  /// Whether the initial analysis is complete.
  bool _analysisComplete = false;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    _runAnalysis();
  }

  /// Runs the complete password health analysis.
  ///
  /// This performs three checks in sequence:
  /// 1. Entropy analysis (instant, local)
  /// 2. Reuse detection (instant, local)
  /// 3. Breach check (async, network — k-Anonymity)
  Future<void> _runAnalysis() async {
    final weakItems = <_AuditResult>[];
    final reusedItems = <_AuditResult>[];
    final healthyItems = <_AuditResult>[];

    // ---- Step 1: Entropy Analysis ----
    // Calculate Shannon entropy for each password and classify strength.
    for (final item in widget.items) {
      final entropy =
          SecurityEngine.calculateShannonEntropy(item.password);
      final strength = SecurityEngine.entropyToStrengthLabel(entropy);

      final result = _AuditResult(
        item: item,
        entropyBits: entropy,
        strength: strength,
      );

      if (strength == 'Weak') {
        weakItems.add(result);
      } else {
        healthyItems.add(result);
      }
    }

    // ---- Step 2: Reuse Detection ----
    // Group items by password to find duplicates.
    final passwordGroups = <String, List<VaultItem>>{};
    for (final item in widget.items) {
      passwordGroups.putIfAbsent(item.password, () => []).add(item);
    }

    // Any password used by more than one item is "reused".
    for (final entry in passwordGroups.entries) {
      if (entry.value.length > 1) {
        for (final item in entry.value) {
          final entropy =
              SecurityEngine.calculateShannonEntropy(item.password);
          reusedItems.add(_AuditResult(
            item: item,
            entropyBits: entropy,
            strength: SecurityEngine.entropyToStrengthLabel(entropy),
            reusedCount: entry.value.length,
          ));

          // Remove from healthy if it was there.
          healthyItems.removeWhere((r) => r.item.id == item.id);
        }
      }
    }

    setState(() {
      _weakPasswords = weakItems;
      _reusedPasswords = reusedItems;
      _healthyPasswords = healthyItems;
      _analysisComplete = true;
    });

    // ---- Step 3: Breach Check (k-Anonymity) ----
    await _checkBreaches();
  }

  /// Checks passwords against the HIBP API using k-Anonymity.
  ///
  /// k-Anonymity protocol:
  /// 1. Hash the password with SHA-1.
  /// 2. Send only the first 5 hex characters to the API.
  /// 3. The API returns all hashes starting with those 5 characters.
  /// 4. We check if our full hash is in the response.
  ///
  /// This ensures the API server never sees our full hash, and the set of
  /// ~800 returned hashes provides plausible deniability (k-anonymity).
  ///
  /// Rate limiting: We add a 200ms delay between requests to be respectful
  /// to the free HIBP API.
  Future<void> _checkBreaches() async {
    setState(() => _isCheckingBreaches = true);

    final breachedItems = <_AuditResult>[];

    for (final item in widget.items) {
      try {
        final isBreached = await _checkPasswordBreach(item.password);
        if (isBreached) {
          final entropy =
              SecurityEngine.calculateShannonEntropy(item.password);
          breachedItems.add(_AuditResult(
            item: item,
            entropyBits: entropy,
            strength: SecurityEngine.entropyToStrengthLabel(entropy),
            isBreached: true,
          ));

          // Remove from healthy if it was there.
          _healthyPasswords.removeWhere((r) => r.item.id == item.id);
        }
      } catch (e) {
        // Network error — skip this item silently.
        // Breach checking is best-effort; network issues shouldn't
        // break the audit.
      }

      // Rate limit: 200ms between API calls.
      await Future.delayed(const Duration(milliseconds: 200));
    }

    if (mounted) {
      setState(() {
        _breachedPasswords = breachedItems;
        _isCheckingBreaches = false;
      });
    }
  }

  /// Checks a single password against HIBP using k-Anonymity.
  ///
  /// Returns true if the password has been found in any known data breach.
  ///
  /// [password] — The plaintext password to check.
  Future<bool> _checkPasswordBreach(String password) async {
    // Step 1: SHA-1 hash the password.
    // Note: SHA-1 is used here because that's what HIBP's API requires.
    // We're not using SHA-1 for security — it's just a lookup key.
    final bytes = utf8.encode(password);
    final sha1Hash = sha1.convert(bytes).toString().toUpperCase();

    // Step 2: Split into prefix (first 5 chars) and suffix (rest).
    final prefix = sha1Hash.substring(0, 5);
    final suffix = sha1Hash.substring(5);

    // Step 3: Query the HIBP API with only the prefix.
    // The API returns ~800 hash suffixes that share this prefix.
    final response = await http.get(
      Uri.parse('https://api.pwnedpasswords.com/range/$prefix'),
      headers: {
        'Add-Padding': 'true', // Request padding to prevent response-length attacks
      },
    );

    if (response.statusCode != 200) {
      throw Exception('HIBP API returned status ${response.statusCode}');
    }

    // Step 4: Check if our suffix appears in the response.
    // Response format: SUFFIX:COUNT\r\n per line
    final lines = response.body.split('\r\n');
    for (final line in lines) {
      final parts = line.split(':');
      if (parts.isNotEmpty && parts[0] == suffix) {
        return true; // Password found in breaches
      }
    }

    return false; // Password not found
  }

  // ---------------------------------------------------------------------------
  // UI
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      appBar: AppBar(
        backgroundColor: const Color(0xFF161B22),
        title: const Text(
          'Security Audit',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: !_analysisComplete
          ? const Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircularProgressIndicator(color: Color(0xFF1A73E8)),
                  SizedBox(height: 16),
                  Text(
                    'Analyzing password health...',
                    style: TextStyle(color: Colors.white54),
                  ),
                ],
              ),
            )
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // ----- Overall Score Card -----
                  _buildScoreCard(),
                  const SizedBox(height: 24),

                  // ----- Pie Chart -----
                  _buildPieChart(),
                  const SizedBox(height: 24),

                  // ----- Breach Check Status -----
                  if (_isCheckingBreaches)
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.blue.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(12),
                        border:
                            Border.all(color: Colors.blue.withOpacity(0.3)),
                      ),
                      child: const Row(
                        children: [
                          SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: Colors.blue,
                            ),
                          ),
                          SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              'Checking passwords against known breaches...\n'
                              '(Using k-Anonymity — your passwords are never sent)',
                              style:
                                  TextStyle(color: Colors.blue, fontSize: 13),
                            ),
                          ),
                        ],
                      ),
                    ),
                  const SizedBox(height: 16),

                  // ----- Breached Passwords Section -----
                  if (_breachedPasswords.isNotEmpty)
                    _buildSection(
                      title: 'Breached Passwords',
                      icon: Icons.dangerous,
                      color: Colors.red,
                      items: _breachedPasswords,
                      description:
                          'These passwords were found in known data breaches. '
                          'Change them immediately.',
                    ),

                  // ----- Weak Passwords Section -----
                  if (_weakPasswords.isNotEmpty)
                    _buildSection(
                      title: 'Weak Passwords',
                      icon: Icons.warning_amber,
                      color: Colors.orange,
                      items: _weakPasswords,
                      description:
                          'These passwords have less than 50 bits of entropy '
                          'and are vulnerable to brute-force attacks.',
                    ),

                  // ----- Reused Passwords Section -----
                  if (_reusedPasswords.isNotEmpty)
                    _buildSection(
                      title: 'Reused Passwords',
                      icon: Icons.content_copy,
                      color: Colors.amber,
                      items: _reusedPasswords,
                      description:
                          'These passwords are shared across multiple accounts. '
                          'If one account is breached, all are compromised.',
                    ),

                  // ----- Healthy Passwords Section -----
                  if (_healthyPasswords.isNotEmpty)
                    _buildSection(
                      title: 'Healthy Passwords',
                      icon: Icons.check_circle,
                      color: Colors.green,
                      items: _healthyPasswords,
                      description: 'These passwords meet security standards.',
                    ),
                ],
              ),
            ),
    );
  }

  /// Builds the overall security score card.
  Widget _buildScoreCard() {
    final total = widget.items.length;
    if (total == 0) {
      return const SizedBox.shrink();
    }

    final issueCount = _weakPasswords.length +
        _reusedPasswords.length +
        _breachedPasswords.length;

    // Remove duplicates (a password can be both weak AND reused).
    final uniqueIssueIds = <String>{};
    for (final r in _weakPasswords) {
      uniqueIssueIds.add(r.item.id);
    }
    for (final r in _reusedPasswords) {
      uniqueIssueIds.add(r.item.id);
    }
    for (final r in _breachedPasswords) {
      uniqueIssueIds.add(r.item.id);
    }

    final healthyCount = total - uniqueIssueIds.length;
    final scorePercent = total > 0 ? (healthyCount / total * 100).round() : 0;

    final scoreColor = scorePercent >= 80
        ? Colors.green
        : scorePercent >= 50
            ? Colors.orange
            : Colors.red;

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: scoreColor.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          // Score circle
          Container(
            width: 72,
            height: 72,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: scoreColor, width: 3),
            ),
            child: Center(
              child: Text(
                '$scorePercent%',
                style: TextStyle(
                  color: scoreColor,
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
          const SizedBox(width: 20),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Vault Health Score',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '$healthyCount of $total passwords are healthy',
                  style: const TextStyle(color: Colors.white54, fontSize: 13),
                ),
                if (issueCount > 0)
                  Text(
                    '${uniqueIssueIds.length} password${uniqueIssueIds.length != 1 ? 's' : ''} need attention',
                    style: TextStyle(color: scoreColor, fontSize: 13),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  /// Builds the pie chart showing password health distribution.
  Widget _buildPieChart() {
    // Remove duplicate IDs across categories for accurate pie chart.
    final breachedIds = _breachedPasswords.map((r) => r.item.id).toSet();
    final weakIds = _weakPasswords
        .map((r) => r.item.id)
        .where((id) => !breachedIds.contains(id))
        .toSet();
    final reusedIds = _reusedPasswords
        .map((r) => r.item.id)
        .where((id) => !breachedIds.contains(id) && !weakIds.contains(id))
        .toSet();

    final healthyCount =
        widget.items.length - breachedIds.length - weakIds.length - reusedIds.length;

    // If no items, show nothing.
    if (widget.items.isEmpty) return const SizedBox.shrink();

    final sections = <PieChartSectionData>[];

    if (breachedIds.isNotEmpty) {
      sections.add(PieChartSectionData(
        value: breachedIds.length.toDouble(),
        title: '${breachedIds.length}',
        color: Colors.red,
        radius: 50,
        titleStyle: const TextStyle(
          color: Colors.white,
          fontSize: 14,
          fontWeight: FontWeight.bold,
        ),
      ));
    }

    if (weakIds.isNotEmpty) {
      sections.add(PieChartSectionData(
        value: weakIds.length.toDouble(),
        title: '${weakIds.length}',
        color: Colors.orange,
        radius: 50,
        titleStyle: const TextStyle(
          color: Colors.white,
          fontSize: 14,
          fontWeight: FontWeight.bold,
        ),
      ));
    }

    if (reusedIds.isNotEmpty) {
      sections.add(PieChartSectionData(
        value: reusedIds.length.toDouble(),
        title: '${reusedIds.length}',
        color: Colors.amber,
        radius: 50,
        titleStyle: const TextStyle(
          color: Colors.white,
          fontSize: 14,
          fontWeight: FontWeight.bold,
        ),
      ));
    }

    if (healthyCount > 0) {
      sections.add(PieChartSectionData(
        value: healthyCount.toDouble(),
        title: '$healthyCount',
        color: Colors.green,
        radius: 50,
        titleStyle: const TextStyle(
          color: Colors.white,
          fontSize: 14,
          fontWeight: FontWeight.bold,
        ),
      ));
    }

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF161B22),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        children: [
          const Text(
            'Password Health Distribution',
            style: TextStyle(
              color: Colors.white,
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 16),
          SizedBox(
            height: 200,
            child: PieChart(
              PieChartData(
                sections: sections,
                centerSpaceRadius: 40,
                sectionsSpace: 2,
              ),
            ),
          ),
          const SizedBox(height: 16),
          // Legend
          Wrap(
            spacing: 16,
            runSpacing: 8,
            children: [
              if (breachedIds.isNotEmpty)
                _buildLegendItem('Breached', Colors.red),
              if (weakIds.isNotEmpty)
                _buildLegendItem('Weak', Colors.orange),
              if (reusedIds.isNotEmpty)
                _buildLegendItem('Reused', Colors.amber),
              _buildLegendItem('Healthy', Colors.green),
            ],
          ),
        ],
      ),
    );
  }

  /// Builds a legend item for the pie chart.
  Widget _buildLegendItem(String label, Color color) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 12,
          height: 12,
          decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(3),
          ),
        ),
        const SizedBox(width: 6),
        Text(
          label,
          style: const TextStyle(color: Colors.white54, fontSize: 12),
        ),
      ],
    );
  }

  /// Builds a collapsible section for a category of audit results.
  Widget _buildSection({
    required String title,
    required IconData icon,
    required Color color,
    required List<_AuditResult> items,
    required String description,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(width: 8),
            Text(
              '$title (${items.length})',
              style: TextStyle(
                color: color,
                fontSize: 16,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        Text(
          description,
          style: const TextStyle(color: Colors.white38, fontSize: 12),
        ),
        const SizedBox(height: 8),
        ...items.map((result) => _buildAuditItemCard(result, color)),
        const SizedBox(height: 16),
      ],
    );
  }

  /// Builds a card for a single audit result.
  Widget _buildAuditItemCard(_AuditResult result, Color color) {
    return Card(
      color: const Color(0xFF161B22),
      margin: const EdgeInsets.only(bottom: 6),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
        side: BorderSide(color: color.withOpacity(0.2)),
      ),
      child: ListTile(
        dense: true,
        leading: CircleAvatar(
          backgroundColor: color.withOpacity(0.15),
          radius: 18,
          child: Text(
            result.item.title.isNotEmpty
                ? result.item.title[0].toUpperCase()
                : '?',
            style: TextStyle(color: color, fontWeight: FontWeight.bold),
          ),
        ),
        title: Text(
          result.item.title,
          style: const TextStyle(color: Colors.white, fontSize: 14),
        ),
        subtitle: Text(
          'Entropy: ${result.entropyBits.toStringAsFixed(1)} bits — ${result.strength}'
          '${result.reusedCount != null ? ' • Reused ${result.reusedCount}x' : ''}'
          '${result.isBreached ? ' • BREACHED' : ''}',
          style: TextStyle(color: color.withOpacity(0.7), fontSize: 11),
        ),
        trailing: Icon(
          result.isBreached
              ? Icons.dangerous
              : result.strength == 'Weak'
                  ? Icons.warning
                  : Icons.info_outline,
          color: color,
          size: 18,
        ),
      ),
    );
  }
}

// =============================================================================
// AUDIT RESULT MODEL
// =============================================================================

/// Represents the audit analysis result for a single vault item.
///
/// This is an ephemeral data structure — it exists only in memory during
/// the audit and is never persisted to disk.
class _AuditResult {
  /// The vault item being analyzed.
  final VaultItem item;

  /// Shannon entropy of the password in bits.
  final double entropyBits;

  /// Human-readable strength label (Weak/Good/Excellent).
  final String strength;

  /// Number of times this password is reused (null if not reused).
  final int? reusedCount;

  /// Whether this password was found in known data breaches.
  final bool isBreached;

  _AuditResult({
    required this.item,
    required this.entropyBits,
    required this.strength,
    this.reusedCount,
    this.isBreached = false,
  });
}
