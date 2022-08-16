package gelato

func GetStatus(taskID string) (*GetResponse, error) {
	endpoint := GelatoRelayURL + "/tasks/GelatoMetaBox" + taskID
	resp, err := getRPC(endpoint)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
