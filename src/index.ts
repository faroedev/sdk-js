import { decodeBase64, encodeBase64 } from "@oslojs/encoding";

export class Faroe {
	private url: string;
	private secret: string | null;

	constructor(url: string, secret: string | null) {
		this.url = url;
		this.secret = secret;
	}

	private async fetchNoBody(method: string, path: string, body: string | null): Promise<void> {
		let response: Response;
		try {
			const request = new Request(this.url + path, {
				method,
				body
			});
			if (this.secret !== null) {
				request.headers.set("Authorization", this.secret);
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
			throw new FaroeError(response.status, result.error);
		}
	}

	private async fetchJSON(method: string, path: string, body: string | null): Promise<unknown> {
		let response: Response;
		try {
			const request = new Request(this.url + path, {
				method,
				body
			});
			if (this.secret !== null) {
				request.headers.set("Authorization", this.secret);
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
			throw new FaroeError(response.status, result.error);
		}
		const result = await response.json();
		return result;
	}

	public async createUser(email: string, password: string, clientIP: string | null): Promise<FaroeUser> {
		const body = JSON.stringify({
			email: email,
			password: password,
			client_ip: clientIP
		});
		const result = await this.fetchJSON("POST", "/users", body);
		const user = parseUserJSON(result);
		return user;
	}

	public async getUser(userId: string): Promise<FaroeUser | null> {
		try {
			const result = await this.fetchJSON("GET", `/users/${userId}`, null);
			const user = parseUserJSON(result);
			return user;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async getUsers(options?: {
		sortBy?: UserSortBy;
		sortOrder?: SortOrder;
		perPage?: number;
		page?: number;
		emailQuery?: string;
	}): Promise<PaginationResult<FaroeUser>> {
		const searchParams = new URLSearchParams();

		const sortBy: UserSortBy = options?.sortBy ?? UserSortBy.CreatedAt;
		if (sortBy === UserSortBy.CreatedAt) {
			searchParams.set("sort_by", "created_at");
		} else if (sortBy === UserSortBy.Id) {
			searchParams.set("sort_by", "id");
		} else if (sortBy === UserSortBy.Email) {
			searchParams.set("sort_by", "email");
		}

		const sortOrder: SortOrder = options?.sortOrder ?? SortOrder.Ascending;
		if (sortOrder === SortOrder.Ascending) {
			searchParams.set("sort_order", "ascending");
		} else if (sortOrder === SortOrder.Descending) {
			searchParams.set("sort_order", "descending");
		}

		const perPage = options?.perPage ?? 20;
		searchParams.set("per_page", perPage.toString());

		const page = options?.page ?? 1;
		searchParams.set("page", page.toString());

		if (options !== undefined && options.emailQuery !== undefined) {
			searchParams.set("email_query", options.emailQuery.toString());
		}

		let response: Response;
		try {
			const request = new Request(this.url + `/users?${searchParams.toString()}`);
			if (this.secret !== null) {
				request.headers.set("Authorization", this.secret);
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
			throw new FaroeError(response.status, result.error);
		}
		const totalPagesHeader = response.headers.get("X-Pagination-Total-Pages");
		if (totalPagesHeader === null) {
			throw new Error("Missing 'X-Pagination-Total-Pages' header");
		}
		if (totalPagesHeader.startsWith("0x")) {
			throw new Error("Invalid 'X-Pagination-Total-Pages' header");
		}
		const totalPages = Number.parseInt(totalPagesHeader);
		if (Number.isNaN(totalPages)) {
			throw new Error("Invalid 'X-Pagination-Total-Pages' header");
		}

		const totalUsersHeader = response.headers.get("X-Pagination-Total");
		if (totalUsersHeader === null) {
			throw new Error("Missing 'X-Pagination-Total' header");
		}
		if (totalUsersHeader.startsWith("0x")) {
			throw new Error("Invalid 'X-Pagination-Total' header");
		}
		const totalUsers = Number.parseInt(totalUsersHeader);
		if (Number.isNaN(totalUsers)) {
			throw new Error("Invalid 'X-Pagination-Total' header");
		}

		const result: unknown = await response.json();
		if (!Array.isArray(result)) {
			throw new Error("Failed to parse result");
		}
		const paginationResult: PaginationResult<FaroeUser> = {
			total: totalUsers,
			totalPages,
			items: []
		};
		for (let i = 0; i < result.length; i++) {
			paginationResult.items.push(parseUserJSON(result[i]));
		}
		return paginationResult;
	}

	public async deleteUser(userId: string): Promise<void> {
		try {
			await this.fetchNoBody("DELETE", `/users/${userId}`, null);
		} catch (e) {
			if (e instanceof FaroeError === false || e.code !== "NOT_FOUND") {
				throw e;
			}
		}
	}

	public async updateUserPassword(
		userId: string,
		password: string,
		newPassword: string,
		clientIP: string | null
	): Promise<void> {
		const body = JSON.stringify({
			password: password,
			new_password: newPassword,
			client_ip: clientIP
		});
		await this.fetchNoBody("POST", `/users/${userId}/update-password`, body);
	}

	public async resetUser2FA(userId: string, recoveryCode: string): Promise<string> {
		const body = JSON.stringify({
			recovery_code: recoveryCode
		});
		const result = await this.fetchJSON("POST", `/users/${userId}/reset-2fa`, body);
		const newRecoveryCode = parseRecoveryCodeJSON(result);
		return newRecoveryCode;
	}

	public async regenerateUserRecoveryCode(userId: string): Promise<string> {
		const result = await this.fetchJSON("POST", `/users/${userId}/regenerate-recovery-code`, null);
		const newRecoveryCode = parseRecoveryCodeJSON(result);
		return newRecoveryCode;
	}

	public async authenticateWithPassword(email: string, password: string, clientIP: string | null): Promise<FaroeUser> {
		const body = JSON.stringify({
			email: email,
			password: password,
			client_ip: clientIP
		});
		const result = await this.fetchJSON("POST", "/authenticate/password", body);
		const user = parseUserJSON(result);
		return user;
	}

	public async createUserEmailVerificationRequest(userId: string): Promise<FaroeUserEmailVerificationRequest> {
		const result = await this.fetchJSON("POST", `/users/${userId}/email-verification-request`, null);
		const verificationRequest = parseUserEmailVerificationRequestJSON(result);
		return verificationRequest;
	}

	public async verifyUserEmail(userId: string, code: string): Promise<void> {
		const body = JSON.stringify({
			code: code
		});
		await this.fetchNoBody("POST", `/users/${userId}/verify-email`, body);
	}

	public async deleteUserEmailVerificationRequest(userId: string): Promise<void> {
		try {
			await this.fetchNoBody("DELETE", `/users/${userId}/email-verification-request`, null);
		} catch (e) {
			if (e instanceof FaroeError === false || e.code !== "NOT_FOUND") {
				throw e;
			}
		}
	}

	public async getUserEmailVerificationRequest(userId: string): Promise<FaroeUserEmailVerificationRequest | null> {
		try {
			const result = await this.fetchJSON("GET", `/users/${userId}/email-verification-request`, null);
			const verificationRequest = parseUserEmailVerificationRequestJSON(result);
			return verificationRequest;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async registerUserTOTPCredential(
		userId: string,
		key: Uint8Array,
		code: string
	): Promise<FaroeUserTOTPCredential> {
		const body = JSON.stringify({
			key: encodeBase64(key),
			code: code
		});
		const result = await this.fetchJSON("POST", `/users/${userId}/register-totp`, body);
		const credential = parseUserTOTPCredentialJSON(result);
		return credential;
	}

	public async getUserTOTPCredential(userId: string): Promise<FaroeUserTOTPCredential | null> {
		try {
			const result = await this.fetchJSON("GET", `/users/${userId}/totp-credential`, null);
			const credential = parseUserTOTPCredentialJSON(result);
			return credential;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async verifyUser2FAWithTOTP(userId: string, code: string): Promise<void> {
		const body = JSON.stringify({
			code: code
		});
		await this.fetchNoBody("POST", `/users/${userId}/verify-2fa/totp`, body);
	}

	public async deleteUserTOTPCredential(userId: string): Promise<void> {
		try {
			await this.fetchNoBody("DELETE", `/users/${userId}/totp-credential`, null);
		} catch (e) {
			if (e instanceof FaroeError === false || e.code !== "NOT_FOUND") {
				throw e;
			}
		}
	}

	public async createUserEmailUpdateRequest(userId: string, email: string): Promise<FaroeEmailUpdateRequest> {
		const body = JSON.stringify({
			email
		});
		const result = await this.fetchJSON("POST", `/users/${userId}/email-update-requests`, body);
		const verificationRequest = parseEmailUpdateRequestJSON(result);
		return verificationRequest;
	}

	public async getUserEmailUpdateRequests(userId: string): Promise<FaroeEmailUpdateRequest[] | null> {
		let result: unknown;
		try {
			result = await this.fetchJSON("GET", `/users/${userId}/email-update-requests`, null);
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
		if (!Array.isArray(result)) {
			throw new Error("Failed to parse result");
		}
		const updateRequests: FaroeEmailUpdateRequest[] = [];
		for (let i = 0; i < result.length; i++) {
			updateRequests.push(parseEmailUpdateRequestJSON(result[i]));
		}
		return updateRequests;
	}

	public async deleteUserEmailUpdateRequests(userId: string): Promise<void> {
		try {
			await this.fetchNoBody("GET", `/users/${userId}/email-update-requests`, null);
		} catch (e) {
			if (e instanceof FaroeError === false || e.code !== "NOT_FOUND") {
				throw e;
			}
		}
	}

	public async updateUserEmail(requestId: string, code: string): Promise<string> {
		const body = JSON.stringify({
			request_id: requestId,
			code: code
		});
		const result = await this.fetchJSON("POST", `/update-email`, body);
		if (typeof result !== "object" || result === null) {
			throw new Error("Failed to parse email");
		}
		if ("email" in result === false || typeof result.email !== "string") {
			throw new Error("Failed to parse email");
		}
		return result.email;
	}

	public async deleteEmailUpdateRequest(requestId: string): Promise<void> {
		try {
			await this.fetchNoBody("DELETE", `/email-update-requests/${requestId}`, null);
		} catch (e) {
			if (e instanceof FaroeError === false || e.code !== "NOT_FOUND") {
				throw e;
			}
		}
	}

	public async getEmailUpdateRequest(requestId: string): Promise<FaroeEmailUpdateRequest | null> {
		try {
			const result = await this.fetchJSON("GET", `/email-update-requests/${requestId}`, null);
			const verificationRequest = parseEmailUpdateRequestJSON(result);
			return verificationRequest;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async createPasswordResetRequest(
		email: string,
		clientIP: string | null
	): Promise<[request: FaroePasswordResetRequest, code: string]> {
		const body = JSON.stringify({
			email: email,
			client_ip: clientIP
		});
		const result = await this.fetchJSON("POST", `/password-reset-requests`, body);
		if (typeof result !== "object" || result === null) {
			throw new Error("Failed to parse result object");
		}
		if ("code" in result === false || typeof result.code !== "string") {
			throw new Error("Failed to parse result object");
		}
		const resetRequest = parsePasswordResetRequestJSON(result);
		return [resetRequest, result.code];
	}

	public async getPasswordResetRequest(requestId: string): Promise<FaroePasswordResetRequest | null> {
		try {
			const result = await this.fetchJSON("GET", `/password-reset-requests/${requestId}`, null);
			const resetRequest = parsePasswordResetRequestJSON(result);
			return resetRequest;
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
	}

	public async deletePasswordResetRequest(requestId: string): Promise<void> {
		try {
			await this.fetchNoBody("DELETE", `/password-reset-requests/${requestId}`, null);
		} catch (e) {
			if (e instanceof FaroeError === false || e.code !== "NOT_FOUND") {
				throw e;
			}
		}
	}

	public async verifyPasswordResetRequestEmail(
		requestId: string,
		code: string,
		clientIP: string | null
	): Promise<void> {
		const body = JSON.stringify({
			code: code,
			client_ip: clientIP
		});
		await this.fetchNoBody("POST", `/password-reset-requests/${requestId}/verify-email`, body);
	}

	public async resetUserPassword(requestId: string, password: string, clientIP: string | null): Promise<void> {
		const body = JSON.stringify({
			request_id: requestId,
			password: password,
			client_ip: clientIP
		});
		await this.fetchNoBody("POST", `/reset-password`, body);
	}

	public async getUserPasswordResetRequests(userId: string): Promise<FaroePasswordResetRequest[] | null> {
		let result: unknown;
		try {
			result = await this.fetchJSON("GET", `/users/${userId}/password-reset-requests`, null);
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				return null;
			}
			throw e;
		}
		if (!Array.isArray(result)) {
			throw new Error("Failed to parse result");
		}
		const resetRequests: FaroePasswordResetRequest[] = [];
		for (let i = 0; i < result.length; i++) {
			resetRequests.push(parsePasswordResetRequestJSON(result[i]));
		}
		return resetRequests;
	}

	public async deleteUserPasswordResetRequests(userId: string): Promise<void> {
		try {
			await this.fetchNoBody("GET", `/users/${userId}/password-reset-requests`, null);
		} catch (e) {
			if (e instanceof FaroeError === false || e.code !== "NOT_FOUND") {
				throw e;
			}
		}
	}
}

export enum UserSortBy {
	CreatedAt = 0,
	Id,
	Email
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
	public status: number;
	public code: string;

	constructor(status: number, code: string) {
		super("Faroe error");
		this.status = status;
		this.code = code;
	}
}

export interface FaroeUser {
	id: string;
	createdAt: Date;
	email: string;
	recoveryCode: string;
	totpRegistered: boolean;
}

export interface FaroeUserEmailVerificationRequest {
	userId: string;
	createdAt: Date;
	expiresAt: Date;
	code: string;
}

export interface FaroeEmailUpdateRequest {
	id: string;
	userId: string;
	createdAt: Date;
	expiresAt: Date;
	email: string;
	code: string;
}

export interface FaroeUserTOTPCredential {
	userId: string;
	createdAt: Date;
	key: Uint8Array;
}

export interface FaroePasswordResetRequest {
	id: string;
	userId: string;
	createdAt: Date;
	expiresAt: Date;
}

export interface PaginationResult<T> {
	total: number;
	totalPages: number;
	items: T[];
}

export function verifyPasswordInput(password: string): boolean {
	return password.length >= 8 && password.length < 128;
}

export function verifyEmailInput(email: string): boolean {
	return email.length > 0 && email.length < 256 && email.trim() === email && /^.+@.+\..+$/.test(email);
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
	if ("recovery_code" in data === false || typeof data.recovery_code !== "string") {
		throw new Error("Failed to parse user object");
	}
	if ("totp_registered" in data === false || typeof data.totp_registered !== "boolean") {
		throw new Error("Failed to parse user object");
	}
	const user: FaroeUser = {
		id: data.id,
		createdAt: new Date(data.created_at * 1000),
		email: data.email,
		recoveryCode: data.recovery_code,
		totpRegistered: data.totp_registered
	};
	return user;
}

function parseUserEmailVerificationRequestJSON(data: unknown): FaroeUserEmailVerificationRequest {
	if (typeof data !== "object" || data === null) {
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
	if ("code" in data === false || typeof data.code !== "string") {
		throw new Error("Failed to parse email verification request object");
	}
	const request: FaroeUserEmailVerificationRequest = {
		userId: data.user_id,
		createdAt: new Date(data.created_at * 1000),
		expiresAt: new Date(data.expires_at * 1000),
		code: data.code
	};
	return request;
}

function parseEmailUpdateRequestJSON(data: unknown): FaroeEmailUpdateRequest {
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
	const request: FaroeEmailUpdateRequest = {
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
	const request: FaroePasswordResetRequest = {
		id: data.id,
		userId: data.user_id,
		createdAt: new Date(data.created_at * 1000),
		expiresAt: new Date(data.expires_at * 1000)
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

function parseUserTOTPCredentialJSON(data: unknown): FaroeUserTOTPCredential {
	if (typeof data !== "object" || data === null) {
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
	const credential: FaroeUserTOTPCredential = {
		userId: data.user_id,
		createdAt: new Date(data.created_at * 1000),
		key: decodeBase64(data.key)
	};
	return credential;
}
