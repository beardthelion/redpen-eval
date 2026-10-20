// Source: https://github.com/getkin/kin-openapi
// Ref: 9245cef66c840e27a08409a8a5cd0ee930c5bcff Path: openapi3filter/req_resp_decoder.go
// Excerpted and modified from https://github.com/getkin/kin-openapi@9245cef66c840e27a08409a8a5cd0ee930c5bcff on 2026-10-20
// License: MIT, see licenses/getkin__kin-openapi/LICENSE
// Copyright (c) 2017-2018 the project authors.
func (d *urlValuesDecoder) parseArray(raw []string, schemaRef *openapi3.SchemaRef) ([]any, error) {
	var value []any

	for i, v := range raw {
		item, err := d.parseValue(v, schemaRef.Value.Items)
		if err != nil {
			if v, ok := err.(*ParseError); ok {
				return nil, &ParseError{path: []any{i}, Cause: v}
			}
			return nil, fmt.Errorf("item %d: %w", i, err)
		}

		// If the items are nil, then the array is nil. There shouldn't be case where some values are actual primitive
		// values and some are nil values.
		if item == nil {
			return nil, nil
		}
		value = append(value, item)
	}
	// If the array has only one element and that element is an empty string, it means no value exists, so return nil.
	if len(value) == 1 {
		if str, ok := value[0].(string); ok && str == "" {
			return nil, nil
		}
	}
	return value, nil
}
// ... lines 617-1030 omitted ...
func buildResObj(params map[string]any, parentKeys []string, key string, schema *openapi3.SchemaRef) (any, error) {
	mapKeys := parentKeys
	if key != "" {
		mapKeys = append(mapKeys, key)
	}

	switch {
	case schema.Value.Type.Is("array"):
		paramArr, ok := deepGet(params, mapKeys...)
		if !ok {
			return nil, nil
		}
		t, isMap := paramArr.(map[string]any)
		if !isMap {
			return nil, &ParseError{path: pathFromKeys(mapKeys), Kind: KindInvalidFormat, Reason: "array items must be set with indexes"}
		}
		// intermediate arrays have to be instantiated
		arr, err := sliceMapToSlice(t)
		if err != nil {
			return nil, &ParseError{path: pathFromKeys(mapKeys), Kind: KindInvalidFormat, Reason: fmt.Sprintf("could not convert value map to array: %v", err)}
		}
		resultArr := make([]any /*not 0,*/, len(arr))
		for i := range arr {
			r, err := buildResObj(params, mapKeys, strconv.Itoa(i), schema.Value.Items)
			if err != nil {
				return nil, err
			}
			if r != nil {
				resultArr[i] = r
			}
		}
		return resultArr, nil
	case schema.Value.Type.Is("object"):
		resultMap := make(map[string]any)
		additPropsSchema := schema.Value.AdditionalProperties.Schema
		pp, _ := deepGet(params, mapKeys...)
		objectParams, ok := pp.(map[string]any)
		if !ok {
			// not the expected type, but return it either way and leave validation up to ValidateParameter
			return pp, nil
		}
		for k, propSchema := range schema.Value.Properties {
			r, err := buildResObj(params, mapKeys, k, propSchema)
			if err != nil {
				return nil, err
			}
			if r != nil {
				resultMap[k] = r
			}
		}
		if additPropsSchema != nil {
			// dynamic creation of possibly nested objects
			for k := range objectParams {
				r, err := buildResObj(params, mapKeys, k, additPropsSchema)
				if err != nil {
					return nil, err
				}
				if r != nil {
					resultMap[k] = r
				}
			}
		} else if schema.Value.AdditionalProperties.Has != nil && *schema.Value.AdditionalProperties.Has {
			// additionalProperties: true is free-form: retain dynamic values as
			// decoded query-string data, but never overwrite schema-decoded
			// properties.
			for k, v := range objectParams {
				if _, exists := resultMap[k]; !exists {
					resultMap[k] = v
				}
			}
		}

		return resultMap, nil
	case len(schema.Value.AnyOf) > 0:
		return buildFromSchemas(schema.Value.AnyOf, params, parentKeys, key)
	case len(schema.Value.OneOf) > 0:
		return buildFromSchemas(schema.Value.OneOf, params, parentKeys, key)
	case len(schema.Value.AllOf) > 0:
		return buildFromSchemas(schema.Value.AllOf, params, parentKeys, key)
	default:
		val, ok := deepGet(params, mapKeys...)
		if !ok {
			// leave validation up to ValidateParameter. here there really is not parameter set
			return nil, nil
		}
		v, ok := val.(string)
		if !ok {
			return nil, &ParseError{path: pathFromKeys(mapKeys), Kind: KindInvalidFormat, Value: val, Reason: "path is not convertible to primitive"}
		}
		prim, err := parsePrimitive(v, schema)
		if err != nil {
			return nil, handlePropParseError(mapKeys, err)
		}

		return prim, nil
	}
}
