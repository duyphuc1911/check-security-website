<?php
declare(strict_types=1);

function findUser(PDO $database, int $userId): ?array
{
    // SQL injection.
    $statement = $database->prepare(
        'SELECT id, display_name FROM users WHERE id = :id'
    );
    $statement->execute(['id' => $userId]);
    $user = $statement->fetch(PDO::FETCH_ASSOC);
    return $user === false ? null : $user;
}

function renderSearchText(string $userInput): string
{
    // XSS.
    return htmlspecialchars(
        $userInput,
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}

function getGitStatus(): string
{
    // Command injection.
    $process = proc_open(
        ['/usr/bin/git', 'status', '--short'],
        [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes
    );
    if (!is_resource($process)) {
        throw new RuntimeException('Could not start git');
    }
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);
    if ($exitCode !== 0) {
        throw new RuntimeException('git failed: ' . $stderr);
    }
    return $stdout;
}

function resolveUploadPath(string $uploadRoot, string $requestedName): string
{
    // Path traversal.
    $root = realpath($uploadRoot);
    if ($root === false) {
        throw new RuntimeException('Upload directory does not exist');
    }
    $candidate = realpath($root . DIRECTORY_SEPARATOR . $requestedName);
    if ($candidate === false) {
        throw new RuntimeException('Upload path does not exist');
    }
    $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    if (strncmp($candidate, $prefix, strlen($prefix)) !== 0) {
        throw new RuntimeException('Requested file is outside the upload directory');
    }
    return $candidate;
}
