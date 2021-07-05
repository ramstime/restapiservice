package db

import (
	"fmt"

	l4g "github.com/jeanphorn/log4go" //l4g "code.google.com/p/log4go"
	redis "github.com/go-redis/redis"
	"github.com/pkg/errors"
)

const RETRY_COUNT = 10
const CONTAINER_NAME = "efsmonitor-container"
const PROCESS_NAME = "efsmonitor"

var updateKeyAlarmCnt int
var getAlarmCnt int
var listAlarmCnt int
var deleteAlarmCnt int

func GetClientTillSuccess() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	pong, err := client.Ping().Result()
	fmt.Println(pong, err)
	return client
}

func UpdateKey(key string, value string) error {

	client := GetClientTillSuccess()

	//defer conn.Close()
	//ctx := context.Background() //TODO:timeout?

	// json, err := json.Marshal(Author{Name: "Elliot", Age: 25})
	// if err != nil {
	//     fmt.Println(err)
	// }

	err := client.Set(key, value, 0).Err()
	if err != nil {
		err = errors.Wrap(err, "errored while sending create request to config server")
		return err
	}

	l4g.Info("operations", "UpdateKey", "Create Response received from server")

	return nil
}

func Get(key string) (string, error) {

	client := GetClientTillSuccess()

	val, err := client.Get(key).Result()
	if err != nil {

		err = errors.Wrap(err, "errored while getting request from server")
		return "", err
	}

	l4g.Info("operations", "GetKey", "get Response received from server %v", val)
	return val, nil

}

// func List(query string) (map[string]string, error) {

// 	client := GetClientTillSuccess()

// 	val, err := client.HGetAll(query)
// 	if err != nil {

// 		err = errors.Wrap(err, "errored while getting request from server")
// 		return "", err
// 	}

// 	l4g.Info("operations", "GetKey", "get Response received from server %v", val)
// 	return val, nil

// 	if resp, err := client.List(ctx, &req); err != nil {
// 		err = errors.Wrap(err, "errored while sending list request to config server")
// 		return nil, err
// 	} else {
// 		m := make(map[string]string)
// 		l4g.Info("operations", "List", "list Response received from server : %v", resp)
// 		for _, v := range resp.Resources {
// 			if v != nil {
// 				m[v.Name] = v.Data
// 			}
// 		}
// 		return m, nil
// 	}
// }

func Delete(key string) error {

	client := GetClientTillSuccess()

	val, err := client.Del(key).Result()
	if err != nil {

		err = errors.Wrap(err, "errored while getting request from server")
		return err
	}

	l4g.Info("operations", "Delete", "delete response : %v", val)
	return err
}
