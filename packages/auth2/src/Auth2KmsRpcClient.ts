import {
  Configuration,
  KMSRPCApi,
  GetOrCreatePhantomOrganizationMethodEnum,
  CreateWalletMethodEnum,
  GetWalletWithTagMethodEnum,
  GetOrCreateWalletWithTagMethodEnum,
  type KmsRpcRequest,
  type KmsRpcResponseV2,
  type ExternalKmsWallet,
  type ExternalKmsOrganization,
  type KmsWalletWithDerivedAccounts,
  type DerivationInfoSchema,
  type ErrorResponse,
} from "@phantom/openapi-wallet-service";
import axios from "axios";
import { Buffer } from "buffer";
import type { Auth2StamperWithKeyManagement } from "./index";

const DEFAULT_KMS_API_VERSION = "2025-11-24";

export type Auth2KmsClientOptions = {
  apiBaseUrl: string;
  appId: string;
};

export type Auth2KmsGetWalletWithTagArgs = {
  organizationId: string;
  tag: string;
};

export type Auth2KmsCreateWalletArgs = {
  walletName: string;
  organizationId: string;
  tags: Array<string>;
  accounts: Array<DerivationInfoSchema>;
  mnemonicLength: number;
};

/**
 * Handles authenticated KMS JSON-RPC calls and org/wallet discovery.
 * Shared between browser and RN Auth2 providers.
 *
 * Uses KMSRPCApi from @phantom/openapi-wallet-service (the same client as
 * PhantomClient) so stamping, headers, and request serialization are handled
 * consistently via axios interceptors rather than manual fetch calls.
 */
export class Auth2KmsRpcClient {
  private readonly kmsApi: KMSRPCApi;

  constructor(
    private readonly stamper: Auth2StamperWithKeyManagement,
    options: Auth2KmsClientOptions,
  ) {
    const axiosInstance = axios.create();

    axiosInstance.interceptors.request.use(async config => {
      await this.stamper.maybeRefreshTokens();

      config.headers = config.headers || {};
      config.headers["x-app-id"] = options.appId;
      config.headers["x-api-version"] = DEFAULT_KMS_API_VERSION;

      config.headers["authorization"] = this.stamper.bearerToken;
      const authUserId = this.stamper.auth2Token?.sub;
      if (authUserId) {
        config.headers["x-auth-user-id"] = authUserId;
      }

      const requestBody =
        typeof config.data === "string" ? config.data : config.data === undefined ? "" : JSON.stringify(config.data);
      const stamp = await this.stamper.stamp({ data: Buffer.from(requestBody, "utf-8") });
      config.headers["x-phantom-stamp"] = stamp;

      return config;
    });

    const configuration = new Configuration({ basePath: options.apiBaseUrl });
    this.kmsApi = new KMSRPCApi(configuration, options.apiBaseUrl, axiosInstance);
  }

  private async postKmsRpc<T>(request: KmsRpcRequest): Promise<T> {
    const response = await this.kmsApi.postKmsRpc(request).catch((error: unknown) => {
      throw formatKmsHttpError(error, request.method);
    });

    // Surface JSON-RPC level errors (KMS returns HTTP 200 with error body).
    const rpcBody: KmsRpcResponseV2 = response.data;
    if ("error" in rpcBody) {
      throw new Error(`KMS RPC error: ${JSON.stringify(rpcBody.error)}`);
    }

    return rpcBody.result as T;
  }

  public async getOrCreatePhantomOrganization(publicKey: string): Promise<ExternalKmsOrganization> {
    return await this.postKmsRpc<ExternalKmsOrganization>({
      method: GetOrCreatePhantomOrganizationMethodEnum.getOrCreatePhantomOrganization,
      params: { publicKey },
      timestampMs: Date.now(),
    } as KmsRpcRequest);
  }

  // listPendingMigrations is not yet in @phantom/openapi-wallet-service
  public async listPendingMigrations(
    organizationId: string,
  ): Promise<{ pendingMigrations?: Array<{ migrationId?: string }> }> {
    return await this.postKmsRpc<{ pendingMigrations?: Array<{ migrationId?: string }> }>({
      method: "listPendingMigrations",
      params: { organizationId },
      timestampMs: Date.now(),
    } as unknown as KmsRpcRequest);
  }

  // completeWalletTransfer is not yet in @phantom/openapi-wallet-service
  public async completeWalletTransfer(args: { organizationId: string; migrationId: string }): Promise<unknown> {
    return await this.postKmsRpc({
      method: "completeWalletTransfer",
      params: args,
      timestampMs: Date.now(),
    } as unknown as KmsRpcRequest);
  }

  public async getWalletWithTag(args: Auth2KmsGetWalletWithTagArgs): Promise<ExternalKmsWallet | null> {
    const wallet = await this.postKmsRpc<ExternalKmsWallet | null>({
      method: GetWalletWithTagMethodEnum.getWalletWithTag,
      params: args,
      timestampMs: Date.now(),
    } as unknown as KmsRpcRequest);

    return wallet ?? null;
  }

  public async createWallet(args: Auth2KmsCreateWalletArgs): Promise<ExternalKmsWallet> {
    return await this.postKmsRpc<ExternalKmsWallet>({
      method: CreateWalletMethodEnum.createWallet,
      params: args,
      timestampMs: Date.now(),
    } as unknown as KmsRpcRequest);
  }

  public async getOrCreateWalletWithTag(args: {
    organizationId: string;
    walletName: string;
    tag: string;
    accounts: Array<DerivationInfoSchema>;
    mnemonicLength: number;
  }): Promise<KmsWalletWithDerivedAccounts> {
    return await this.postKmsRpc<KmsWalletWithDerivedAccounts>({
      method: GetOrCreateWalletWithTagMethodEnum.getOrCreateWalletWithTag,
      params: args,
      timestampMs: Date.now(),
    } as KmsRpcRequest);
  }
}

type KmsHttpResponse = {
  status: number;
  data: unknown;
  headers: unknown;
};

// Edge/WAF blocks don't use the ErrorResponse shape, so we only trust ids that look like opaque identifiers.
const SAFE_ID = /^[A-Za-z0-9-]{1,64}$/;

function readSafeId(value: unknown): string | undefined {
  return typeof value === "string" && SAFE_ID.test(value) ? value : undefined;
}

function readHeader(headers: unknown, name: string): unknown {
  if (typeof headers !== "object" || headers === null) {
    return undefined;
  }
  const h = headers as { get?: (key: string) => unknown } & Record<string, unknown>;
  return typeof h.get === "function" ? h.get(name) : h[name];
}

function getHttpResponse(error: unknown): KmsHttpResponse | null {
  if (typeof error !== "object" || error === null || !("response" in error)) {
    return null;
  }

  const response = (error as { response?: { status?: unknown; data?: unknown; headers?: unknown } }).response;
  if (!response || typeof response.status !== "number") {
    return null;
  }

  return { status: response.status, data: response.data, headers: response.headers };
}

/**
 * MCP returns only `error.message`. Keep ErrorResponse fields and drop request
 * headers, tokens, stamps, and the Axios config.
 */
function formatKmsHttpError(error: unknown, method: string): unknown {
  const response = getHttpResponse(error);
  if (!response) {
    return error;
  }

  let detail: string | undefined;
  let requestId: string | undefined;
  if (response.data && typeof response.data === "object") {
    const body = response.data as Partial<ErrorResponse>;
    if (typeof body.error === "string" && body.error.length > 0) {
      detail = body.error;
    }
    if (typeof body.requestId === "string" && body.requestId.length > 0) {
      requestId = body.requestId;
    }
    // Edge blocks reply with { success, message, id } instead of ErrorResponse.
    requestId ??= readSafeId((response.data as { id?: unknown }).id);
  }
  const cfRay = readSafeId(readHeader(response.headers, "cf-ray"));

  let message = `KMS HTTP ${response.status}`;
  if (detail) {
    message += `: ${detail}`;
  }
  message += ` (method=${method}`;
  if (requestId) {
    message += ` requestId=${requestId}`;
  }
  if (cfRay) {
    message += ` cf-ray=${cfRay}`;
  }
  message += ")";
  return new Error(message);
}
