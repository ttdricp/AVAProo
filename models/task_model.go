package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type StructA struct {
	FieldA string `form:"Till date"`
}

type Task struct {
	ID          primitive.ObjectID `bson:"_id"`
	Name        *string            `form:"Task name" validate:"required,min=2,max=100"`
	Category    *string            `form:"Category"`
	Description *string            `form:"Description"`
	Points      *int               `form:"Points"`
	Till_date   *time.Time         `json:"TillDate"`
	Created_at  time.Time          `json:"created_at"`
	Updated_at  time.Time          `json:"updated_at"`
	Task_id     string             `json:"task_id"`
}
