"use strict";

const path = require("node:path");
const { realpath, readFile } = require("node:fs/promises");
const { execFile } = require("node:child_process");

async function findUser(database, userId) {
  // SQL injection.
  return database.query(
    "SELECT id, display_name FROM users WHERE id = $1",
    [userId]
  );
}

function renderSearchText(container, userInput) {
  // XSS.
  container.textContent = userInput;
}

function getGitStatus() {
  // Command injection.
  return new Promise((resolve, reject) => {
    execFile("git", ["status", "--short"], { shell: false }, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(stdout);
    });
  });
}

async function readUpload(uploadRoot, requestedName) {
  // Path traversal.
  const root = await realpath(uploadRoot);
  const candidate = await realpath(path.resolve(root, requestedName));
  const relative = path.relative(root, candidate);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("Requested file is outside the upload directory");
  }
  return readFile(candidate);
}

module.exports = { findUser, renderSearchText, getGitStatus, readUpload };
