// Source: https://github.com/TanStack/router
// Ref: 614bc27034c8ec98747bf305ed41d4a619640949 Path: packages/start-server-core/src/server-functions-handler.ts
// Excerpted and modified from https://github.com/TanStack/router@614bc27034c8ec98747bf305ed41d4a619640949 on 2026-10-20
// License: MIT, see licenses/TanStack__router/LICENSE
// Copyright (c) 2021-present Tanner Linsley
export const handleServerAction = async ({
  request,
  context,
  serverFnId,
}: {
  request: Request
  context: any
  serverFnId: string
}) => {
  const methodUpper = request.method.toUpperCase()
  const url = new URL(request.url)

  const action = await getServerFnById(serverFnId, { origin: 'client' })

  // Early method check: reject mismatched HTTP methods before parsing
  // the request payload (FormData, JSON, query string, etc.)
  if (action.method && methodUpper !== action.method) {
    return new Response(
      `expected ${action.method} method. Got ${methodUpper}`,
      {
        status: 405,
        headers: {
          Allow: action.method,
        },
      },
    )
  }

  const isServerFn = request.headers.get('x-tsr-serverFn') === 'true'
  // Initialize serovalPlugins lazily (cached at module level)
  serovalPlugins ??= getSerovalPlugins(routerDefaultSerovalPlugins)
  const contentType = request.headers.get('Content-Type')

  try {
    let res: any
    if (
      FORM_DATA_CONTENT_TYPES.some(
        (type) => contentType && contentType.includes(type),
      )
    ) {
      // We don't support GET requests with FormData payloads... that seems impossible
      if (methodUpper === 'GET') {
        if (process.env.NODE_ENV !== 'production') {
          throw new Error(
            'Invariant failed: GET requests with FormData payloads are not supported',
          )
        }

        invariant()
      }
      const formData = await request.formData()
      const serializedContext = formData.get(TSS_FORMDATA_CONTEXT)
      formData.delete(TSS_FORMDATA_CONTEXT)

      const params = {
        context,
        data: formData,
        method: methodUpper,
      }
      if (typeof serializedContext === 'string') {
        try {
          const parsedContext = JSON.parse(serializedContext)
          const deserializedContext = fromJSON(parsedContext, {
            plugins: serovalPlugins,
          })
          if (typeof deserializedContext === 'object' && deserializedContext) {
            params.context = safeObjectMerge(
              deserializedContext as Record<string, unknown>,
              context,
            )
          }
        } catch (e) {
          // Log warning for debugging but don't expose to client
          if (process.env.NODE_ENV === 'development') {
            console.warn('Failed to parse FormData context:', e)
          }
        }
      }

      res = await action(params)
    } else if (methodUpper === 'GET') {
      // Get payload directly from searchParams
      const payloadParam = url.searchParams.get('payload')
      // Reject oversized payloads to prevent DoS
      if (payloadParam && payloadParam.length > MAX_PAYLOAD_SIZE) {
        throw new Error('Payload too large')
      }
      const payload: any = payloadParam
        ? fromJSON(JSON.parse(payloadParam), { plugins: serovalPlugins })
        : {}
      payload.context = safeObjectMerge(payload.context, context)
      payload.method = methodUpper
      res = await action(payload)
    } else {
      const payload: any = contentType?.includes('application/json')
        ? fromJSON(await request.json(), { plugins: serovalPlugins })
        : {}
      payload.context = safeObjectMerge(payload.context, context)
      payload.method = methodUpper
      res = await action(payload)
    }

    const unwrapped = res.result !== undefined ? res.result : res.error

    if (isNotFound(res)) {
      res = isNotFoundResponse(res)
    }

    if (!isServerFn) {
      return unwrapped
    }

    if (unwrapped instanceof Response) {
      if (isRedirect(unwrapped)) {
        return unwrapped
      }
      unwrapped.headers.set(X_TSS_RAW_RESPONSE, 'true')
      return unwrapped
    }

    return serializeResult(res, request.signal, serovalPlugins)
  } catch (error: any) {
    if (error instanceof Response) {
      return error
    }

    // Currently this server-side context has no idea how to
    // build final URLs, so we need to defer that to the client.
    // The client will check for __redirect and __notFound keys,
    // and if they exist, it will handle them appropriately.

    if (isNotFound(error)) {
      return isNotFoundResponse(error)
    }

    console.error('Server Fn Error!', error)

    const serializedError = JSON.stringify(
      await toCrossJSONAsync(error, {
        refs: new Map(),
        plugins: serovalPlugins,
      }),
    )
    const response = getResponse()
    const headers = {
      'Content-Type': 'application/json',
      [X_TSS_SERIALIZED]: 'true',
    }
    try {
      return new Response(serializedError, {
        status: response.status ?? 500,
        statusText: response.statusText,
        headers,
      })
    } catch {
      return new Response(serializedError, {
        status: 500,
        statusText: '',
        headers,
      })
    }
  }
}
// ... lines 232-517 omitted ...
function isNotFoundResponse(error: any) {
  const { headers, ...rest } = error

  return new Response(JSON.stringify(rest), {
    status: 404,
    headers: {
      'Content-Type': 'application/json',
      ...(headers || {}),
    },
  })
}
