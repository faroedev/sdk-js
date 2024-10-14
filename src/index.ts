import { decodeBase64, encodeBase64 } from "@oslojs/encoding";

export class Faroe {
	private url: string;
	private secret: string;

	constructor(url: string, secret: string) {
		this.url = url;
		this.secret = secret;
	}

	private async fetchNoBody(method: string, path: string, body: string | null, clientIP: string | null): Promise<void> {
		let response: Response;
		try {
			const request = new Request(this.url + path, {
				method,
				body
			});
			request.headers.set("Authorization", this.secret);
			if (clientIP !== null) {
				request.headers.set("X-Client-IP", clientIP);
			}
			response = await fetch(request);
		} catch (e) {
			throw new FaroeFetchError(e);
		}
		if (!response.ok) {
			const result = await response.json();
			if (typeof result !== "object" || result === null) {
				throw new Error("Unexpected error response");
			}
			if ("error" in result === false || typeof result.error !== "string") {
				throw new Error("Unexpected error response");
			}
			throw new FaroeError(result.error);
		}
	}

	private async fetchJSON(
		method: string,
		path: string,
		body: string | null,
		clientIP: string | null
	): Promise<unknown> {
		let response: Response;
		try {
			const request = new Request(this.url + path, {
				method,
				body
			});
			request.headers.set("Authorization", this.secret);
			if (clientIP !== null) {
				request.headers.set("X-Client-IP", clientIP);
			}
			response = await fetch(request);
		} catch (e) {
			throw new FaroeFetchError(e);
		}
		if (!response.ok) {
			const result = await response.json();
			if (typeof result !== "object" || result === null) {
				throw new Error("Unexpected error response");
			}
			if ("error" in result === false || typeof result.error !== "string") {
				throw new Error("Unexpected error response");
			}
			throw new FaroeError(result.error);
		}
		const result = await response.json();
		return result;
	}

	public async createUser(email: string, password: string, clientIP: string | null): Promise<FaroeUser> {
		const body = JSON.stringify({
			email: email,
			password: password
		});
		const result = await this.fetchJSON("POST", "/users", body, clientIP);
		const user = parseUserJSON(result);
		return user;
	}

	public async getUser(userId: string, clientIP: string | null): Promise<FaroeUser | null> {
		try {
			const result = await this.fetchJSON("GET", `/users/${userId}`, null, clientIP);
			const user = parseUserJSON(result);
			return user;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async getUsers(
		sortBy: UserSortBy,
		sortOrder: SortOrder,
		count: number,
		page: number,
		clientIP: string | null
	): Promise<FaroeUser[]> {
		const searchParams = new URLSearchParams();
		if (sortBy === UserSortBy.CreatedAt) {
			searchParams.set("sort_by", "created_at");
		}
		if (sortOrder === SortOrder.Ascending) {
			searchParams.set("sort_by", "ascending");
		} else if (sortOrder === SortOrder.Descending) {
			searchParams.set("sort_by", "descending");
		}
		searchParams.set("count", count.toString());
		searchParams.set("page", page.toString());
		const result = await this.fetchJSON("GET", `/users?${searchParams.toString()}`, null, clientIP);
		if (!Array.isArray(result)) {
			throw new Error("Failed to parse result");
		}
		const users: FaroeUser[] = [];
		for (let i = 0; i < users.length; i++) {
			users.push(parseUserJSON(result[i]));
		}
		return users;
	}

	public async deleteUser(userId: string, clientIP: string | null): Promise<void> {
		await this.fetchNoBody("DELETE", `/users/${userId}`, null, clientIP);
	}

	public async updateUserPassword(
		userId: string,
		password: string,
		newPassword: string,
		clientIP: string | null
	): Promise<void> {
		const body = JSON.stringify({
			password: password,
			new_password: newPassword
		});
		await this.fetchNoBody("POST", `/users/${userId}`, body, clientIP);
	}

	public async resetUser2FA(userId: string, recoveryCode: string, clientIP: string | null): Promise<string> {
		const body = JSON.stringify({
			recovery_code: recoveryCode
		});
		const result = await this.fetchJSON("POST", `/users/${userId}/reset-2fa`, body, clientIP);
		const newRecoveryCode = parseRecoveryCodeJSON(result);
		return newRecoveryCode;
	}

	public async regenerateUserRecoveryCode(userId: string, clientIP: string | null): Promise<string> {
		const result = await this.fetchJSON("POST", `/users/${userId}/regenerate-recovery-code`, null, clientIP);
		const newRecoveryCode = parseRecoveryCodeJSON(result);
		return newRecoveryCode;
	}

	public async authenticateWithPassword(email: string, password: string, clientIP: string | null): Promise<FaroeUser> {
		const body = JSON.stringify({
			email: email,
			password: password
		});
		const result = await this.fetchJSON("POST", "/authenticate/password", body, clientIP);
		const user = parseUserJSON(result);
		return user;
	}

	public async createUserEmailVerificationRequest(
		userId: string,
		email: string,
		clientIP: string | null
	): Promise<FaroeEmailVerificationRequest> {
		const body = JSON.stringify({
			email: email
		});
		const result = await this.fetchJSON("POST", `/users/${userId}/email-verification`, body, clientIP);
		const verificationRequest = parseEmailVerificationRequestJSON(result);
		return verificationRequest;
	}

	public async verifyUserEmailVerificationRequest(
		userId: string,
		requestId: string,
		code: string,
		clientIP: string | null
	): Promise<FaroeUser> {
		const body = JSON.stringify({
			request_id: requestId,
			code: code
		});
		const result = await this.fetchJSON("POST", `/users/${userId}/verify-email`, body, clientIP);
		const user = parseUserJSON(result);
		return user;
	}

	public async deleteUserEmailVerificationRequest(
		userId: string,
		requestId: string,
		clientIP: string | null
	): Promise<void> {
		await this.fetchNoBody("DELETE", `/users/${userId}/email-verification/${requestId}`, null, clientIP);
	}

	public async getUserEmailVerificationRequest(
		userId: string,
		requestId: string,
		clientIP: string | null
	): Promise<FaroeEmailVerificationRequest> {
		const result = await this.fetchJSON("GET", `/users/${userId}/email-verification/${requestId}`, null, clientIP);
		const verificationRequest = parseEmailVerificationRequestJSON(result);
		return verificationRequest;
	}

	public async registerUserTOTPCredential(
		userId: string,
		key: Uint8Array,
		code: string,
		clientIP: string | null
	): Promise<string> {
		const body = JSON.stringify({
			key: encodeBase64(key),
			code: code
		});
		const result = await this.fetchJSON("POST", `/users/${userId}/totp`, body, clientIP);
		const newRecoveryCode = parseRecoveryCodeJSON(result);
		return newRecoveryCode;
	}

	public async getUserTOTPCredential(userId: string, clientIP: string | null): Promise<FaroeTOTPCredential | null> {
		try {
			const result = await this.fetchJSON("GET", `/users/${userId}/totp`, null, clientIP);
			const credential = parseTOTPCredentialJSON(result);
			return credential;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async verifyUser2FAWithTOTP(userId: string, code: string, clientIP: string | null): Promise<void> {
		const body = JSON.stringify({
			code: code
		});
		await this.fetchNoBody("POST", `/users/${userId}/verify-2fa/totp`, body, clientIP);
	}

	public async deleteUserTOTPCredential(userId: string, clientIP: string | null): Promise<void> {
		await this.fetchNoBody("DELETE", `/users/${userId}/totp`, null, clientIP);
	}

	public async createPasswordResetRequest(email: string, clientIP: string | null): Promise<FaroePasswordResetRequest> {
		const body = JSON.stringify({
			email: email
		});
		const result = await this.fetchJSON("POST", `/password-reset`, body, clientIP);
		const resetRequest = parsePasswordResetRequestJSON(result);
		return resetRequest;
	}

	public async getPasswordResetRequest(
		requestId: string,
		clientIP: string | null
	): Promise<FaroePasswordResetRequest | null> {
		try {
			const result = await this.fetchJSON("GET", `/password-reset/${requestId}`, null, clientIP);
			const resetRequest = parsePasswordResetRequestJSON(result);
			return resetRequest;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async deletePasswordResetRequest(requestId: string, clientIP: string | null): Promise<void> {
		await this.fetchNoBody("DELETE", `/password-reset/${requestId}`, null, clientIP);
	}

	public async verifyPasswordResetRequestEmail(
		requestId: string,
		code: string,
		clientIP: string | null
	): Promise<void> {
		const body = JSON.stringify({
			code: code
		});
		await this.fetchNoBody("POST", `/password-reset/${requestId}/verify-email`, body, clientIP);
	}

	public async verifyPasswordResetRequest2FAWithTOTP(
		requestId: string,
		code: string,
		clientIP: string | null
	): Promise<void> {
		const body = JSON.stringify({
			code: code
		});
		await this.fetchNoBody("POST", `/password-reset/${requestId}/verify-2fa/totp`, body, clientIP);
	}

	public async resetPasswordResetRequestUser2FAWithRecoveryCode(
		requestId: string,
		recoveryCode: string,
		clientIP: string | null
	): Promise<string> {
		const body = JSON.stringify({
			recovery_code: recoveryCode
		});
		const result = await this.fetchJSON("POST", `/password-reset/${requestId}/reset-2fa`, body, clientIP);
		const newRecoveryCode = parseRecoveryCodeJSON(result);
		return newRecoveryCode;
	}

	public async resetUserPassword(requestId: string, password: string, clientIP: string | null): Promise<FaroeUser> {
		const body = JSON.stringify({
			request_id: requestId,
			password: password
		});
		const result = await this.fetchJSON("POST", `/reset-password`, body, clientIP);
		const user = parseUserJSON(result);
		return user;
	}
}

export enum UserSortBy {
	CreatedAt = 0
}

export enum SortOrder {
	Ascending = 0,
	Descending
}

export class FaroeFetchError extends Error {
	constructor(cause: unknown) {
		super("Failed to fetch request", {
			cause
		});
	}
}

export class FaroeError extends Error {
	public code: string;

	constructor(code: string) {
		super("Faroe error");
		this.code = code;
	}
}

export interface FaroeUser {
	id: string;
	createdAt: Date;
	email: string;
	emailVerified: boolean;
	registeredTOTP: boolean;
}

export interface FaroeEmailVerificationRequest {
	id: string;
	userId: string;
	createdAt: Date;
	expiresAt: Date;
	email: string;
	code: string;
}

export interface FaroeTOTPCredential {
	id: string;
	userId: string;
	createdAt: Date;
	key: Uint8Array;
}

export interface FaroePasswordResetRequest {
	id: string;
	userId: string;
	createdAt: Date;
	expiresAt: Date;
	email: string;
	emailVerified: boolean;
	twoFactorVerified: boolean;
}

function parseUserJSON(data: unknown): FaroeUser {
	if (typeof data !== "object" || data === null) {
		throw new Error("Failed to parse user object");
	}
	if ("id" in data === false || typeof data.id !== "string") {
		throw new Error("Failed to parse user object");
	}
	if ("created_at" in data === false || typeof data.created_at !== "number") {
		throw new Error("Failed to parse user object");
	}
	if ("email" in data === false || typeof data.email !== "string") {
		throw new Error("Failed to parse user object");
	}
	if ("email_verified" in data === false || typeof data.email_verified !== "boolean") {
		throw new Error("Failed to parse user object");
	}
	if ("registered_totp" in data === false || typeof data.registered_totp !== "boolean") {
		throw new Error("Failed to parse user object");
	}
	const user: FaroeUser = {
		id: data.id,
		createdAt: new Date(data.created_at * 1000),
		email: data.email,
		emailVerified: data.email_verified,
		registeredTOTP: data.registered_totp
	};
	return user;
}

function parseEmailVerificationRequestJSON(data: unknown): FaroeEmailVerificationRequest {
	if (typeof data !== "object" || data === null) {
		throw new Error("Failed to parse email verification request object");
	}
	if ("id" in data === false || typeof data.id !== "string") {
		throw new Error("Failed to parse email verification request object");
	}
	if ("user_id" in data === false || typeof data.user_id !== "string") {
		throw new Error("Failed to parse email verification request object");
	}
	if ("created_at" in data === false || typeof data.created_at !== "number") {
		throw new Error("Failed to parse email verification request object");
	}
	if ("expires_at" in data === false || typeof data.expires_at !== "number") {
		throw new Error("Failed to parse email verification request object");
	}
	if ("email" in data === false || typeof data.email !== "string") {
		throw new Error("Failed to parse email verification request object");
	}
	if ("code" in data === false || typeof data.code !== "string") {
		throw new Error("Failed to parse email verification request object");
	}
	if ("registered_totp" in data === false || typeof data.registered_totp !== "boolean") {
		throw new Error("Failed to parse email verification request object");
	}
	const request: FaroeEmailVerificationRequest = {
		id: data.id,
		userId: data.user_id,
		createdAt: new Date(data.created_at * 1000),
		expiresAt: new Date(data.expires_at * 1000),
		email: data.email,
		code: data.code
	};
	return request;
}

function parsePasswordResetRequestJSON(data: unknown): FaroePasswordResetRequest {
	if (typeof data !== "object" || data === null) {
		throw new Error("Failed to parse password reset request object");
	}
	if ("id" in data === false || typeof data.id !== "string") {
		throw new Error("Failed to parse password reset request object");
	}
	if ("user_id" in data === false || typeof data.user_id !== "string") {
		throw new Error("Failed to parse password reset request object");
	}
	if ("created_at" in data === false || typeof data.created_at !== "number") {
		throw new Error("Failed to parse password reset request object");
	}
	if ("expires_at" in data === false || typeof data.expires_at !== "number") {
		throw new Error("Failed to parse password reset request object");
	}
	if ("email" in data === false || typeof data.email !== "string") {
		throw new Error("Failed to parse password reset request object");
	}
	if ("email_verified" in data === false || typeof data.email_verified !== "boolean") {
		throw new Error("Failed to parse password reset request object");
	}
	if ("two_factor_verified" in data === false || typeof data.two_factor_verified !== "boolean") {
		throw new Error("Failed to parse password reset request object");
	}
	const request: FaroePasswordResetRequest = {
		id: data.id,
		userId: data.user_id,
		createdAt: new Date(data.created_at * 1000),
		expiresAt: new Date(data.expires_at * 1000),
		email: data.email,
		emailVerified: data.email_verified,
		twoFactorVerified: data.two_factor_verified
	};
	return request;
}

function parseRecoveryCodeJSON(data: unknown): string {
	if (typeof data !== "object" || data === null) {
		throw new Error("Failed to parse recovery code");
	}
	if ("recovery_code" in data === false || typeof data.recovery_code !== "string") {
		throw new Error("Failed to parse recovery code");
	}
	return data.recovery_code;
}

function parseTOTPCredentialJSON(data: unknown): FaroeTOTPCredential {
	if (typeof data !== "object" || data === null) {
		throw new Error("Failed to parse TOTP credential object");
	}
	if ("id" in data === false || typeof data.id !== "string") {
		throw new Error("Failed to parse TOTP credential object");
	}
	if ("user_id" in data === false || typeof data.user_id !== "string") {
		throw new Error("Failed to parse TOTP credential object");
	}
	if ("created_at" in data === false || typeof data.created_at !== "number") {
		throw new Error("Failed to parse TOTP credential object");
	}
	if ("key" in data === false || typeof data.key !== "string") {
		throw new Error("Failed to parse TOTP credential object");
	}
	const credential: FaroeTOTPCredential = {
		id: data.id,
		userId: data.user_id,
		createdAt: new Date(data.created_at * 1000),
		key: decodeBase64(data.key)
	};
	return credential;
}
