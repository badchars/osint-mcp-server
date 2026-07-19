interface XquikRequestOptions {
  path: string;
  apiKey: string;
  searchParams?: Record<string, string | number | boolean | undefined>;
}

const XQUIK_API_BASE_URL = "https://xquik.com/api/v1";

function buildXquikUrl(path: string, searchParams?: XquikRequestOptions["searchParams"]): string {
  const url = new URL(`${XQUIK_API_BASE_URL}${path}`);

  for (const [key, value] of Object.entries(searchParams ?? {})) {
    if (value !== undefined && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }

  return url.toString();
}

async function xquikGet(options: XquikRequestOptions): Promise<unknown> {
  const res = await fetch(buildXquikUrl(options.path, options.searchParams), {
    headers: {
      Accept: "application/json",
      "x-api-key": options.apiKey,
    },
  });

  const contentType = res.headers.get("content-type") ?? "";
  const body: unknown = contentType.includes("application/json")
    ? await res.json()
    : { message: await res.text() };

  if (!res.ok) {
    const message = typeof body === "object" && body !== null && "message" in body
      ? String((body as { message?: unknown }).message)
      : `Xquik returned ${res.status}`;
    throw new Error(message);
  }

  return body;
}

export async function xquikTweet(tweetId: string, apiKey: string): Promise<unknown> {
  return xquikGet({
    path: `/x/tweets/${encodeURIComponent(tweetId)}`,
    apiKey,
  });
}

export async function xquikSearchTweets(
  query: string,
  apiKey: string,
  limit?: number,
  queryType?: string,
  cursor?: string,
): Promise<unknown> {
  return xquikGet({
    path: "/x/tweets/search",
    apiKey,
    searchParams: {
      q: query,
      limit,
      queryType,
      cursor,
    },
  });
}

export async function xquikUser(userIdOrUsername: string, apiKey: string): Promise<unknown> {
  return xquikGet({
    path: `/x/users/${encodeURIComponent(userIdOrUsername)}`,
    apiKey,
  });
}
