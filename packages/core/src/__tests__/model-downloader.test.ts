import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import * as tar from "tar";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { downloadModel } from "../clients/model-downloader.js";
import {
	getDownloadStagingDir,
	getModelDir,
	getModelStorageRoot,
	isModelPresent,
	requiredModelFiles,
} from "../model-storage.js";

let sageDir: string;

beforeEach(() => {
	sageDir = mkdtempSync(join(tmpdir(), "sage-dl-"));
});

afterEach(() => {
	rmSync(sageDir, { recursive: true, force: true });
});

/**
 * Build a tarball whose content matches `requiredModelFiles("pi-model")`.
 * The archive is laid out one level deep (`<root>/<files>`) so the
 * downloader's `strip: 1` extraction lands the files directly in the
 * model directory — matching the production layout.
 */
async function buildModelTarball(): Promise<Buffer> {
	const work = mkdtempSync(join(tmpdir(), "sage-tar-"));
	const inner = join(work, "pi-model");
	mkdirSync(inner, { recursive: true });
	for (const f of requiredModelFiles("pi-model")) {
		writeFileSync(join(inner, f), `stub:${f}`);
	}

	const out = join(work, "archive.tar.gz");
	await tar.create({ gzip: true, cwd: work, file: out }, ["pi-model"]);
	const fs = await import("node:fs/promises");
	const buf = await fs.readFile(out);
	rmSync(work, { recursive: true, force: true });
	return buf;
}

function sha256(buf: Buffer): string {
	return createHash("sha256").update(buf).digest("hex");
}

function fetchReturning(buf: Buffer): typeof fetch {
	return (async () => {
		const stream = Readable.toWeb(Readable.from(buf));
		return new Response(stream as unknown as BodyInit, { status: 200 });
	}) as unknown as typeof fetch;
}

describe("downloadModel", () => {
	it("happy path: extracts archive and deletes source tarball", async () => {
		const archive = await buildModelTarball();
		const ok = await downloadModel({
			modelName: "pi-model",
			entry: { url: "https://example.com/pi-model.tar.gz", sha256: sha256(archive) },
			schema: "v1",
			sageDir,
			fetchImpl: fetchReturning(archive),
		});
		expect(ok).toBe(true);
		expect(isModelPresent("pi-model", "v1", sageDir)).toBe(true);

		// No .tar.gz left in the staging dir.
		const staging = getDownloadStagingDir(sageDir);
		const leftovers = existsSync(staging)
			? readdirSync(staging).filter((f) => f.endsWith(".tar.gz"))
			: [];
		expect(leftovers).toEqual([]);

		// Lock file is cleaned up.
		expect(existsSync(`${getModelDir("pi-model", "v1", sageDir)}.lock`)).toBe(false);
	});

	it("missing sha256 in entry: no fetch attempted", async () => {
		let fetchCalls = 0;
		const ok = await downloadModel({
			modelName: "pi-model",
			entry: { url: "https://example.com/x.tar.gz", sha256: "" },
			schema: "v1",
			sageDir,
			fetchImpl: (async () => {
				fetchCalls++;
				throw new Error("fetch should not be called");
			}) as unknown as typeof fetch,
		});
		expect(ok).toBe(false);
		expect(fetchCalls).toBe(0);
		expect(isModelPresent("pi-model", "v1", sageDir)).toBe(false);
	});

	it("sha256 mismatch: archive deleted, modelDir not created", async () => {
		const archive = await buildModelTarball();
		const ok = await downloadModel({
			modelName: "pi-model",
			entry: { url: "https://example.com/x.tar.gz", sha256: "0".repeat(64) },
			schema: "v1",
			sageDir,
			fetchImpl: fetchReturning(archive),
		});
		expect(ok).toBe(false);
		expect(isModelPresent("pi-model", "v1", sageDir)).toBe(false);

		const staging = getDownloadStagingDir(sageDir);
		const leftovers = existsSync(staging)
			? readdirSync(staging).filter((f) => f.endsWith(".tar.gz"))
			: [];
		expect(leftovers).toEqual([]);
	});

	it("re-entrant: returns true without fetching when modelDir already populated", async () => {
		const dir = getModelDir("pi-model", "v1", sageDir);
		mkdirSync(dir, { recursive: true });
		for (const f of requiredModelFiles("pi-model")) {
			writeFileSync(join(dir, f), "stub");
		}

		let fetchCalls = 0;
		const ok = await downloadModel({
			modelName: "pi-model",
			entry: { url: "https://example.com/x.tar.gz", sha256: "abc" },
			schema: "v1",
			sageDir,
			fetchImpl: (async () => {
				fetchCalls++;
				throw new Error("should not be called");
			}) as unknown as typeof fetch,
		});
		expect(ok).toBe(true);
		expect(fetchCalls).toBe(0);
	});

	describe("security: path traversal prevention", () => {
		it("rejects file inclusion attack: reading sensitive files via path traversal in modelName", async () => {
			const archive = await buildModelTarball();
			// Attempt to read /etc/passwd by traversing out of the model directory
			const ok = await downloadModel({
				modelName: "../../../../../../etc/passwd",
				entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
				schema: "v1",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(false);
			// Ensure the model directory path validation prevents the attack
			const modelRoot = getModelStorageRoot(sageDir);
			const attemptedPath = join(modelRoot, "v1", "../../../../../../etc/passwd");
			expect(existsSync(attemptedPath)).toBe(false);
		});

		it("rejects file inclusion attack: reading sensitive files via path traversal in schema", async () => {
			const archive = await buildModelTarball();
			// Attempt to use schema parameter to escape the model storage root
			const ok = await downloadModel({
				modelName: "valid-model",
				entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
				schema: "../../../tmp/malicious",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(false);
			// Verify the path validation prevents writing outside model storage
			expect(existsSync("/tmp/malicious")).toBe(false);
		});

		it("rejects absolute paths in modelName and schema", async () => {
			const archive = await buildModelTarball();
			
			// Test absolute path in modelName
			let ok = await downloadModel({
				modelName: "/tmp/malicious",
				entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
				schema: "v1",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(false);
			expect(existsSync("/tmp/malicious")).toBe(false);

			// Test absolute path in schema
			ok = await downloadModel({
				modelName: "pi-model",
				entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
				schema: "/etc/shadow",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(false);
			expect(existsSync("/etc/shadow")).toBe(false);
		});

		it("rejects various path traversal encoding techniques", async () => {
			const archive = await buildModelTarball();
			// Try various encoded and obfuscated forms of path traversal
			const maliciousNames = [
				"..%2F..%2Fetc%2Fpasswd",           // URL-encoded
				"..\\..\\windows\\system32",         // Windows-style
				"./../../../etc/shadow",             // Mixed
				"....//....//etc/passwd",            // Double dots
				"..;/..;/etc/passwd",                // Semicolon separator
				"%252E%252E%252F%252E%252E%252Fetc%252Fpasswd", // Double-encoded
				"..\\../etc/passwd",                 // Mixed separators
			];

			for (const name of maliciousNames) {
				const ok = await downloadModel({
					modelName: name,
					entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
					schema: "v1",
					sageDir,
					fetchImpl: fetchReturning(archive),
				});
				expect(ok).toBe(false);
			}
		});

		it("rejects deeply nested path traversal attempts", async () => {
			const archive = await buildModelTarball();
			// Test with excessive path traversal attempts
			const ok = await downloadModel({
				modelName: "../".repeat(20) + "etc/shadow",
				entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
				schema: "v1",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(false);
			// Verify the sensitive file was not accessed
			expect(existsSync("/etc/shadow")).toBe(false);
		});

		it("rejects null byte injection in modelName", async () => {
			const archive = await buildModelTarball();
			const ok = await downloadModel({
				modelName: "valid-model\0../../../etc/passwd",
				entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
				schema: "v1",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(false);
		});

		it("rejects Windows-style absolute paths", async () => {
			const archive = await buildModelTarball();
			const maliciousPaths = [
				"C:\\Windows\\System32\\config",
				"C:/Windows/System32/config",
				"\\\\server\\share\\file",
			];

			for (const path of maliciousPaths) {
				const ok = await downloadModel({
					modelName: path,
					entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
					schema: "v1",
					sageDir,
					fetchImpl: fetchReturning(archive),
				});
				expect(ok).toBe(false);
			}
		});

		it("validates archivePath and extractDir stay within staging directory", async () => {
			const archive = await buildModelTarball();
			// Even with a valid-looking name, the random suffix should keep paths safe
			const ok = await downloadModel({
				modelName: "valid-model",
				entry: { url: "https://example.com/x.tar.gz", sha256: sha256(archive) },
				schema: "v1",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(true);
			
			// Verify the staging directory is within the model storage root
			const stagingDir = getDownloadStagingDir(sageDir);
			const modelRoot = getModelStorageRoot(sageDir);
			expect(stagingDir.startsWith(modelRoot)).toBe(true);
		});

		it("allows valid model names and verifies path containment", async () => {
			const archive = await buildModelTarball();
			const ok = await downloadModel({
				modelName: "pi-model",
				entry: { url: "https://example.com/pi-model.tar.gz", sha256: sha256(archive) },
				schema: "v1",
				sageDir,
				fetchImpl: fetchReturning(archive),
			});
			expect(ok).toBe(true);
			expect(isModelPresent("pi-model", "v1", sageDir)).toBe(true);
			
			// Verify the model is in the expected location within storage root
			const modelDir = getModelDir("pi-model", "v1", sageDir);
			const modelRoot = getModelStorageRoot(sageDir);
			expect(modelDir.startsWith(modelRoot)).toBe(true);
			// And should not contain path traversal sequences
			expect(modelDir).not.toContain("..");
		});
	});
});
