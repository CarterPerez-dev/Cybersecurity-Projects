/*
CarterPerez-dev | 2026
dockerfile.go
*/

package parser

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type DockerfileAST struct {
	Path     string
	Root     *parser.Node
	Stages   []Stage
	Commands []Command
}

type Stage struct {
	Name      string
	BaseName  string
	BaseTag   string
	StartLine int
	EndLine   int
	Commands  []Command
}

type Command struct {
	Instruction string
	Arguments   []string
	Original    string
	StartLine   int
	EndLine     int
	Stage       int
}

func ParseDockerfile(path string) (*DockerfileAST, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening dockerfile: %w", err)
	}
	defer func() { _ = file.Close() }()

	return ParseDockerfileReader(path, file)
}

func ParseDockerfileReader(path string, r io.Reader) (*DockerfileAST, error) {
	result, err := parser.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parsing dockerfile: %w", err)
	}

	ast := &DockerfileAST{
		Path: path,
		Root: result.AST,
	}

	ast.extractStructure()

	return ast, nil
}

func (d *DockerfileAST) extractStructure() {
	stageIndex := -1

	for _, node := range d.Root.Children {
		instruction := strings.ToUpper(node.Value)

		cmd := Command{
			Instruction: instruction,
			Original:    node.Original,
			StartLine:   node.StartLine,
			EndLine:     node.EndLine,
			Stage:       stageIndex,
		}

		for n := node.Next; n != nil; n = n.Next {
			cmd.Arguments = append(cmd.Arguments, n.Value)
		}

		if instruction == "FROM" {
			stageIndex++
			stage := d.parseFromInstruction(node, stageIndex)
			d.Stages = append(d.Stages, stage)
			cmd.Stage = stageIndex
		}

		d.Commands = append(d.Commands, cmd)

		if stageIndex >= 0 && stageIndex < len(d.Stages) {
			d.Stages[stageIndex].Commands = append(
				d.Stages[stageIndex].Commands,
				cmd,
			)
			d.Stages[stageIndex].EndLine = node.EndLine
		}
	}
}

func (d *DockerfileAST) parseFromInstruction(
	node *parser.Node,
	index int,
) Stage {
	stage := Stage{
		StartLine: node.StartLine,
		EndLine:   node.EndLine,
	}

	if node.Next != nil {
		imageRef := node.Next.Value
		stage.BaseName, stage.BaseTag = parseImageReference(imageRef)
	}

	for n := node.Next; n != nil; n = n.Next {
		if strings.ToUpper(n.Value) == "AS" && n.Next != nil {
			stage.Name = n.Next.Value
			break
		}
	}

	if stage.Name == "" {
		stage.Name = fmt.Sprintf("stage-%d", index)
	}

	return stage
}

func parseImageReference(ref string) (name, tag string) {
	ref = strings.TrimSpace(ref)

	if atIdx := strings.Index(ref, "@"); atIdx != -1 {
		return ref[:atIdx], ref[atIdx:]
	}

	if colonIdx := strings.LastIndex(ref, ":"); colonIdx != -1 {
		possibleTag := ref[colonIdx+1:]
		if !strings.Contains(possibleTag, "/") {
			return ref[:colonIdx], possibleTag
		}
	}

	return ref, "latest"
}

func (d *DockerfileAST) GetInstructions(instruction string) []Command {
	instruction = strings.ToUpper(instruction)
	var result []Command
	for _, cmd := range d.Commands {
		if cmd.Instruction == instruction {
			result = append(result, cmd)
		}
	}
	return result
}

func (d *DockerfileAST) HasInstruction(instruction string) bool {
	return len(d.GetInstructions(instruction)) > 0
}

func (d *DockerfileAST) GetLastInstruction(instruction string) *Command {
	instructions := d.GetInstructions(instruction)
	if len(instructions) == 0 {
		return nil
	}
	return &instructions[len(instructions)-1]
}

func (d *DockerfileAST) GetStageInstructions(
	stageIndex int,
	instruction string,
) []Command {
	instruction = strings.ToUpper(instruction)
	var result []Command
	for _, cmd := range d.Commands {
		if cmd.Stage == stageIndex && cmd.Instruction == instruction {
			result = append(result, cmd)
		}
	}
	return result
}

func (d *DockerfileAST) FinalStage() *Stage {
	if len(d.Stages) == 0 {
		return nil
	}
	return &d.Stages[len(d.Stages)-1]
}

func (d *DockerfileAST) IsMultiStage() bool {
	return len(d.Stages) > 1
}

func (d *DockerfileAST) Visit(visitor DockerfileVisitor) {
	for _, cmd := range d.Commands {
		visitor.VisitCommand(cmd)
	}
}

type DockerfileVisitor interface {
	VisitCommand(cmd Command)
}
