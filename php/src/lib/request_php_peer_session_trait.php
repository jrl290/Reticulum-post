<?php

declare(strict_types=1);

namespace ReticulumPhp;

use PDO;

// Reticulum-php is request-operated. These PHP peer session helpers only
// persist local request-exchange identity and the next remote request target;
// they do not establish a second transport path.

trait RequestPhpPeerSessionTrait
{
    public function ensurePhpPeerLocalSession(string $peerName, ?string $initialRemoteUrl = null): array
    {
        $existing = $this->phpPeerSession($peerName);
        if ($existing !== null) {
            if ($initialRemoteUrl !== null && $existing['remote_url'] === null) {
                $this->setPhpPeerRemoteUrl($peerName, $initialRemoteUrl);
                $existing['remote_url'] = trim($initialRemoteUrl);
            }

            return $existing;
        }

        $localInterfaceId = bin2hex(random_bytes(16));
        $localSessionToken = bin2hex(random_bytes(32));
        $now = time();
        $remoteUrl = $initialRemoteUrl !== null ? trim($initialRemoteUrl) : null;

        $insert = $this->db->prepare(
            'INSERT INTO php_peer_sessions (
                peer_name,
                local_interface_id,
                local_session_token,
                remote_url,
                updated_at
            ) VALUES (
                :peer_name,
                :local_interface_id,
                :local_session_token,
                :remote_url,
                :updated_at
            )'
        );
        $insert->bindValue(':peer_name', $peerName, PDO::PARAM_STR);
        $insert->bindValue(':local_interface_id', $localInterfaceId, PDO::PARAM_STR);
        $insert->bindValue(':local_session_token', $localSessionToken, PDO::PARAM_STR);
        $insert->bindValue(':remote_url', $remoteUrl, $remoteUrl === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $insert->bindValue(':updated_at', $now, PDO::PARAM_INT);
        $insert->execute();

        return [
            'peer_name' => $peerName,
            'local_interface_id' => $localInterfaceId,
            'local_session_token' => $localSessionToken,
            'remote_url' => $remoteUrl,
        ];
    }

    public function ensurePhpPeerRemoteSession(string $remoteUrl): array
    {
        $remoteUrl = trim($remoteUrl);
        $existing = $this->phpPeerSessionByRemoteUrl($remoteUrl);
        if ($existing !== null) {
            return $existing;
        }

        return $this->ensurePhpPeerLocalSession(
            $this->phpPeerRemoteSessionKey($remoteUrl),
            $remoteUrl,
        );
    }

    public function phpPeerSessionByRemoteUrl(string $remoteUrl): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT peer_name, local_interface_id, local_session_token, remote_url
             FROM php_peer_sessions
             WHERE remote_url = :remote_url
             LIMIT 1'
        );
        $stmt->bindValue(':remote_url', trim($remoteUrl), PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }

        $peerName = (string) ($row['peer_name'] ?? '');
        $this->touchPhpPeerSession($peerName);
        return $this->phpPeerSessionFromRow($row);
    }

    public function phpPeerSessionByInterfaceId(string $interfaceId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT peer_name, local_interface_id, local_session_token, remote_url
             FROM php_peer_sessions
             WHERE local_interface_id = :local_interface_id
             LIMIT 1'
        );
        $stmt->bindValue(':local_interface_id', $interfaceId, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }

        $peerName = (string) ($row['peer_name'] ?? '');
        $this->touchPhpPeerSession($peerName);
        return $this->phpPeerSessionFromRow($row);
    }

    public function phpPeerRemoteUrl(string $peerName): ?string
    {
        $stmt = $this->db->prepare(
            'SELECT remote_url
             FROM php_peer_sessions
             WHERE peer_name = :peer_name
             LIMIT 1'
        );
        $stmt->bindValue(':peer_name', $peerName, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }

        $remoteUrl = $row['remote_url'] ?? null;
        if (!is_string($remoteUrl)) {
            return null;
        }

        $remoteUrl = trim($remoteUrl);
        return $remoteUrl === '' ? null : $remoteUrl;
    }

    public function setPhpPeerRemoteUrl(string $peerName, string $remoteUrl): void
    {
        $this->ensurePhpPeerLocalSession($peerName);

        $stmt = $this->db->prepare(
            'UPDATE php_peer_sessions
             SET remote_url = :remote_url,
                 updated_at = :updated_at
             WHERE peer_name = :peer_name'
        );
        $stmt->bindValue(':remote_url', trim($remoteUrl), PDO::PARAM_STR);
        $stmt->bindValue(':updated_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':peer_name', $peerName, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function setPhpPeerRemoteUrlByInterfaceId(string $interfaceId, string $remoteUrl): void
    {
        $stmt = $this->db->prepare(
            'UPDATE php_peer_sessions
             SET remote_url = :remote_url,
                 updated_at = :updated_at
             WHERE local_interface_id = :local_interface_id'
        );
        $stmt->bindValue(':remote_url', trim($remoteUrl), PDO::PARAM_STR);
        $stmt->bindValue(':updated_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':local_interface_id', $interfaceId, PDO::PARAM_STR);
        $stmt->execute();
    }

    public function phpPeerSession(string $peerName): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT peer_name, local_interface_id, local_session_token, remote_url
             FROM php_peer_sessions
             WHERE peer_name = :peer_name
             LIMIT 1'
        );
        $stmt->bindValue(':peer_name', $peerName, PDO::PARAM_STR);
        $row = $stmt->execute(); $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row)) {
            return null;
        }

        $this->touchPhpPeerSession($peerName);
        return $this->phpPeerSessionFromRow($row);
    }

    private function touchPhpPeerSession(string $peerName): void
    {
        $stmt = $this->db->prepare(
            'UPDATE php_peer_sessions
             SET updated_at = :updated_at
             WHERE peer_name = :peer_name'
        );
        $stmt->bindValue(':updated_at', time(), PDO::PARAM_INT);
        $stmt->bindValue(':peer_name', $peerName, PDO::PARAM_STR);
        $stmt->execute();
    }

    private function phpPeerRemoteSessionKey(string $remoteUrl): string
    {
        return '__php_peer_remote__' . substr(hash('sha256', trim($remoteUrl)), 0, 32);
    }

    private function phpPeerSessionFromRow(array $row): array
    {
        return [
            'peer_name' => (string) ($row['peer_name'] ?? ''),
            'local_interface_id' => (string) ($row['local_interface_id'] ?? ''),
            'local_session_token' => (string) ($row['local_session_token'] ?? ''),
            'remote_url' => isset($row['remote_url']) && is_string($row['remote_url']) && trim($row['remote_url']) !== ''
                ? trim((string) $row['remote_url'])
                : null,
        ];
    }
}