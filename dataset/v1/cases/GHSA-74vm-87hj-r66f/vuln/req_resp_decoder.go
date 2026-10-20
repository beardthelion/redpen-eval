// Source: https://github.com/getkin/kin-openapi
// Ref: d090e36b2f1c42c898ba2a687a8f6e25f5ca727f Path: openapi3filter/req_resp_decoder.go
// Excerpted and modified from https://github.com/getkin/kin-openapi@d090e36b2f1c42c898ba2a687a8f6e25f5ca727f on 2026-10-20
// License: MIT, see licenses/getkin__kin-openapi/LICENSE
// Copyright (c) 2017-2018 the project authors.
func decodeValue(dec valueDecoder, param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef, required bool) (any, bool, error) {
	var found bool

	if len(schema.Value.AllOf) > 0 {
		var value any
		var err error
		for _, sr := range schema.Value.AllOf {
			var f bool
			value, f, err = decodeValue(dec, param, sm, sr, required)
			found = found || f
			if value == nil || err != nil {
				break
			}
		}
		return value, found, err
	}

	if len(schema.Value.AnyOf) > 0 {
		for _, sr := range schema.Value.AnyOf {
			value, f, _ := decodeValue(dec, param, sm, sr, required)
			found = found || f
			if value != nil {
				return value, found, nil
			}
		}
		if required {
			return nil, found, fmt.Errorf("decoding anyOf for parameter %q failed", param)
		}
		return nil, found, nil
	}

	if len(schema.Value.OneOf) > 0 {
		isMatched := 0
		var value any
		for _, sr := range schema.Value.OneOf {
			v, f, _ := decodeValue(dec, param, sm, sr, required)
			found = found || f
			if v != nil {
				value = v
				isMatched++
			}
		}
		if isMatched >= 1 {
			return value, found, nil
		}
		if required {
			return nil, found, fmt.Errorf("decoding oneOf failed: %q is required", param)
		}
		return nil, found, nil
	}

	if schema.Value.Not != nil {
		// TODO(decode not): handle decoding "not" JSON Schema
		return nil, found, errors.New("not implemented: decoding 'not'")
	}

	if schema.Value.Type != nil {
		var decodeFn func(param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef) (any, bool, error)
		switch {
		case schema.Value.Type.Is("array"):
			decodeFn = func(param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef) (any, bool, error) {
				res, b, e := dec.DecodeArray(param, sm, schema)
				if len(res) == 0 {
					return nil, b, e
				}
				return res, b, e
			}
		case schema.Value.Type.Is("object"):
			decodeFn = func(param string, sm *openapi3.SerializationMethod, schema *openapi3.SchemaRef) (any, bool, error) {
				return dec.DecodeObject(param, sm, schema)
			}
		default:
			decodeFn = dec.DecodePrimitive
		}
		return decodeFn(param, sm, schema)
	}
	switch vDecoder := dec.(type) {
	case *pathParamDecoder:
		_, found = vDecoder.pathParams[param]
	case *urlValuesDecoder:
		if schema.Value.Pattern != "" {
			return dec.DecodePrimitive(param, sm, schema)
		}
		_, found = vDecoder.values[param]
	case *headerParamDecoder:
		_, found = vDecoder.header[http.CanonicalHeaderKey(param)]
	case *cookieParamDecoder:
		_, err := vDecoder.req.Cookie(param)
		found = err != http.ErrNoCookie
	default:
		return nil, found, errors.New("unsupported decoder")
	}
	return nil, found, nil
}
