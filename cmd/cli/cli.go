package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"
)

type App struct {
	Name                 string
	HelpName             string
	Usage                string
	ArgsUsage            string
	Version              string
	Commands             []Command
	Flags                []Flag
	EnableBashCompletion bool
	HideHelp             bool
	HideVersion          bool
	BashComplete         func(context *Context)
	Before               func(context *Context) error
	After                func(context *Context) error
	Action               func(context *Context) error
	CommandNotFound      func(context *Context, command string)
	Compiled             time.Time
	Authors              []Author
	Copyright            string
	Author               string
	Email                string
	Writer               io.Writer
}

func compileTime() time.Time {
	info, err := os.Stat(os.Args[0])
	if err != nil {
		return time.Now()
	}
	return info.ModTime()
}

func NewApp() *App {
	return &App{
		Name:         os.Args[0],
		HelpName:     os.Args[0],
		Usage:        "A new cli application",
		Version:      "0.0.0",
		BashComplete: DefaultAppComplete,
		Action:       helpCommand.Action,
		Compiled:     compileTime(),
		Writer:       os.Stdout,
	}
}

func (a *App) Run(arguments []string) (err error) {
	if a.Author != "" || a.Email != "" {
		a.Authors = append(a.Authors, Author{Name: a.Author, Email: a.Email})
	}

	newCmds := []Command{}
	for _, c := range a.Commands {
		if c.HelpName == "" {
			c.HelpName = fmt.Sprintf("%s %s", a.HelpName, c.Name)
		}
		newCmds = append(newCmds, c)
	}
	a.Commands = newCmds

	if a.Command(helpCommand.Name) == nil && !a.HideHelp {
		a.Commands = append(a.Commands, helpCommand)
		if (HelpFlag != BoolFlag{}) {
			a.appendFlag(HelpFlag)
		}
	}

	if a.EnableBashCompletion {
		a.appendFlag(BashCompletionFlag)
	}

	if !a.HideVersion {
		a.appendFlag(VersionFlag)
	}

	set := flagSet(a.Name, a.Flags)
	set.SetOutput(ioutil.Discard)
	err = set.Parse(arguments[1:])
	nerr := normalizeFlags(a.Flags, set)
	if nerr != nil {
		fmt.Fprintln(a.Writer, nerr)
		context := NewContext(a, set, nil)
		ShowAppHelp(context)
		return nerr
	}
	context := NewContext(a, set, nil)

	if err != nil {
		fmt.Fprintln(a.Writer, "Incorrect Usage.")
		fmt.Fprintln(a.Writer)
		ShowAppHelp(context)
		return err
	}

	if checkCompletions(context) {
		return nil
	}

	if !a.HideHelp && checkHelp(context) {
		return nil
	}

	if !a.HideVersion && checkVersion(context) {
		return nil
	}

	if a.After != nil {
		defer func() {
			afterErr := a.After(context)
			if afterErr != nil {
				if err != nil {
					err = NewMultiError(err, afterErr)
				} else {
					err = afterErr
				}
			}
		}()
	}

	if a.Before != nil {
		err := a.Before(context)
		if err != nil {
			return err
		}
	}

	args := context.Args()
	if args.Present() {
		name := args.First()
		c := a.Command(name)
		if c != nil {
			return c.Run(context)
		}
	}

	a.Action(context)
	return nil
}

func (a *App) RunAndExitOnError() {
	if err := a.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (a *App) RunAsSubcommand(ctx *Context) (err error) {
	if len(a.Commands) > 0 {
		if a.Command(helpCommand.Name) == nil && !a.HideHelp {
			a.Commands = append(a.Commands, helpCommand)
			if (HelpFlag != BoolFlag{}) {
				a.appendFlag(HelpFlag)
			}
		}
	}

	newCmds := []Command{}
	for _, c := range a.Commands {
		if c.HelpName == "" {
			c.HelpName = fmt.Sprintf("%s %s", a.HelpName, c.Name)
		}
		newCmds = append(newCmds, c)
	}
	a.Commands = newCmds

	if a.EnableBashCompletion {
		a.appendFlag(BashCompletionFlag)
	}

	set := flagSet(a.Name, a.Flags)
	set.SetOutput(ioutil.Discard)
	err = set.Parse(ctx.Args().Tail())
	nerr := normalizeFlags(a.Flags, set)
	context := NewContext(a, set, ctx)

	if nerr != nil {
		fmt.Fprintln(a.Writer, nerr)
		fmt.Fprintln(a.Writer)
		if len(a.Commands) > 0 {
			ShowSubcommandHelp(context)
		} else {
			ShowCommandHelp(ctx, context.Args().First())
		}
		return nerr
	}

	if err != nil {
		fmt.Fprintln(a.Writer, "Incorrect Usage.")
		fmt.Fprintln(a.Writer)
		ShowSubcommandHelp(context)
		return err
	}

	if checkCompletions(context) {
		return nil
	}

	if len(a.Commands) > 0 {
		if checkSubcommandHelp(context) {
			return nil
		}
	} else {
		if checkCommandHelp(ctx, context.Args().First()) {
			return nil
		}
	}

	if a.After != nil {
		defer func() {
			afterErr := a.After(context)
			if afterErr != nil {
				if err != nil {
					err = NewMultiError(err, afterErr)
				} else {
					err = afterErr
				}
			}
		}()
	}

	if a.Before != nil {
		err := a.Before(context)
		if err != nil {
			return err
		}
	}

	args := context.Args()
	if args.Present() {
		name := args.First()
		c := a.Command(name)
		if c != nil {
			return c.Run(context)
		}
	}

	a.Action(context)
	return nil
}

func (a *App) Command(name string) *Command {
	for _, c := range a.Commands {
		if c.HasName(name) {
			return &c
		}
	}
	return nil
}

func (a *App) hasFlag(flag Flag) bool {
	for _, f := range a.Flags {
		if flag == f {
			return true
		}
	}
	return false
}

func (a *App) appendFlag(flag Flag) {
	if !a.hasFlag(flag) {
		a.Flags = append(a.Flags, flag)
	}
}

type Author struct {
	Name  string // The Authors name
	Email string // The Authors email
}

func (a Author) String() string {
	e := ""
	if a.Email != "" {
		e = "<" + a.Email + "> "
	}

	return fmt.Sprintf("%v %v", a.Name, e)
}

type MultiError struct {
	Errors []error
}

func NewMultiError(err ...error) MultiError {
	return MultiError{Errors: err}
}

func (m MultiError) Error() string {
	errs := make([]string, len(m.Errors))
	for i, err := range m.Errors {
		errs[i] = err.Error()
	}

	return strings.Join(errs, "\n")
}

type Command struct {
	Name            string
	ShortName       string
	Aliases         []string
	Usage           string
	Description     string
	ArgsUsage       string
	BashComplete    func(context *Context)
	Before          func(context *Context) error
	After           func(context *Context) error
	Action          func(context *Context) error
	Subcommands     []Command
	Flags           []Flag
	SkipFlagParsing bool
	HideHelp        bool
	HelpName        string
	commandNamePath []string
}

func (c Command) FullName() string {
	if c.commandNamePath == nil {
		return c.Name
	}
	return strings.Join(c.commandNamePath, " ")
}

func (c Command) Run(ctx *Context) error {
	if len(c.Subcommands) > 0 || c.Before != nil || c.After != nil {
		return c.startApp(ctx)
	}

	if !c.HideHelp && (HelpFlag != BoolFlag{}) {
		// append help to flags
		c.Flags = append(
			c.Flags,
			HelpFlag,
		)
	}

	if ctx.App.EnableBashCompletion {
		c.Flags = append(c.Flags, BashCompletionFlag)
	}

	set := flagSet(c.Name, c.Flags)
	set.SetOutput(ioutil.Discard)

	firstFlagIndex := -1
	terminatorIndex := -1
	for index, arg := range ctx.Args() {
		if arg == "--" {
			terminatorIndex = index
			break
		} else if strings.HasPrefix(arg, "-") && firstFlagIndex == -1 {
			firstFlagIndex = index
		}
	}

	var err error
	if firstFlagIndex > -1 && !c.SkipFlagParsing {
		args := ctx.Args()
		regularArgs := make([]string, len(args[1:firstFlagIndex]))
		copy(regularArgs, args[1:firstFlagIndex])

		var flagArgs []string
		if terminatorIndex > -1 {
			flagArgs = args[firstFlagIndex:terminatorIndex]
			regularArgs = append(regularArgs, args[terminatorIndex:]...)
		} else {
			flagArgs = args[firstFlagIndex:]
		}

		err = set.Parse(append(flagArgs, regularArgs...))
	} else {
		err = set.Parse(ctx.Args().Tail())
	}

	if err != nil {
		fmt.Fprintln(ctx.App.Writer, "Incorrect Usage.")
		fmt.Fprintln(ctx.App.Writer)
		ShowCommandHelp(ctx, c.Name)
		return err
	}

	nerr := normalizeFlags(c.Flags, set)
	if nerr != nil {
		fmt.Fprintln(ctx.App.Writer, nerr)
		fmt.Fprintln(ctx.App.Writer)
		ShowCommandHelp(ctx, c.Name)
		return nerr
	}
	context := NewContext(ctx.App, set, ctx)

	if checkCommandCompletions(context, c.Name) {
		return nil
	}

	if checkCommandHelp(context, c.Name) {
		return nil
	}
	context.Command = c
	return c.Action(context)
}

func (c Command) Names() []string {
	names := []string{c.Name}

	if c.ShortName != "" {
		names = append(names, c.ShortName)
	}
	return append(names, c.Aliases...)
}

func (c Command) HasName(name string) bool {
	for _, n := range c.Names() {
		if n == name {
			return true
		}
	}
	return false
}

func (c Command) startApp(ctx *Context) error {
	app := NewApp()

	// set the name and usage
	app.Name = fmt.Sprintf("%s %s", ctx.App.Name, c.Name)
	if c.HelpName == "" {
		app.HelpName = c.HelpName
	} else {
		app.HelpName = fmt.Sprintf("%s %s", ctx.App.Name, c.Name)
	}

	if c.Description != "" {
		app.Usage = c.Description
	} else {
		app.Usage = c.Usage
	}

	// set CommandNotFound
	app.CommandNotFound = ctx.App.CommandNotFound

	// set the flags and commands
	app.Commands = c.Subcommands
	app.Flags = c.Flags
	app.HideHelp = c.HideHelp

	app.Version = ctx.App.Version
	app.HideVersion = ctx.App.HideVersion
	app.Compiled = ctx.App.Compiled
	app.Author = ctx.App.Author
	app.Email = ctx.App.Email
	app.Writer = ctx.App.Writer

	// bash completion
	app.EnableBashCompletion = ctx.App.EnableBashCompletion
	if c.BashComplete != nil {
		app.BashComplete = c.BashComplete
	}

	// set the actions
	app.Before = c.Before
	app.After = c.After
	if c.Action != nil {
		app.Action = c.Action
	} else {
		app.Action = helpSubcommand.Action
	}

	var newCmds []Command
	for _, cc := range app.Commands {
		cc.commandNamePath = []string{c.Name, cc.Name}
		newCmds = append(newCmds, cc)
	}
	app.Commands = newCmds

	return app.RunAsSubcommand(ctx)
}

type Context struct {
	App            *App
	Command        Command
	flagSet        *flag.FlagSet
	setFlags       map[string]bool
	globalSetFlags map[string]bool
	parentContext  *Context
}

func NewContext(app *App, set *flag.FlagSet, parentCtx *Context) *Context {
	return &Context{App: app, flagSet: set, parentContext: parentCtx}
}

func (c *Context) Int(name string) int {
	return lookupInt(name, c.flagSet)
}

func (c *Context) Duration(name string) time.Duration {
	return lookupDuration(name, c.flagSet)
}

func (c *Context) Float64(name string) float64 {
	return lookupFloat64(name, c.flagSet)
}

func (c *Context) Bool(name string) bool {
	return lookupBool(name, c.flagSet)
}

func (c *Context) BoolT(name string) bool {
	return lookupBoolT(name, c.flagSet)
}

func (c *Context) String(name string) string {
	return lookupString(name, c.flagSet)
}

func (c *Context) StringSlice(name string) []string {
	return lookupStringSlice(name, c.flagSet)
}

func (c *Context) IntSlice(name string) []int {
	return lookupIntSlice(name, c.flagSet)
}

func (c *Context) Generic(name string) interface{} {
	return lookupGeneric(name, c.flagSet)
}

func (c *Context) GlobalInt(name string) int {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupInt(name, fs)
	}
	return 0
}

func (c *Context) GlobalDuration(name string) time.Duration {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupDuration(name, fs)
	}
	return 0
}

func (c *Context) GlobalBool(name string) bool {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupBool(name, fs)
	}
	return false
}

func (c *Context) GlobalString(name string) string {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupString(name, fs)
	}
	return ""
}

func (c *Context) GlobalStringSlice(name string) []string {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupStringSlice(name, fs)
	}
	return nil
}

func (c *Context) GlobalIntSlice(name string) []int {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupIntSlice(name, fs)
	}
	return nil
}

func (c *Context) GlobalGeneric(name string) interface{} {
	if fs := lookupGlobalFlagSet(name, c); fs != nil {
		return lookupGeneric(name, fs)
	}
	return nil
}

func (c *Context) NumFlags() int {
	return c.flagSet.NFlag()
}

func (c *Context) IsSet(name string) bool {
	if c.setFlags == nil {
		c.setFlags = make(map[string]bool)
		c.flagSet.Visit(func(f *flag.Flag) {
			c.setFlags[f.Name] = true
		})
	}
	return c.setFlags[name] == true
}

func (c *Context) GlobalIsSet(name string) bool {
	if c.globalSetFlags == nil {
		c.globalSetFlags = make(map[string]bool)
		ctx := c
		if ctx.parentContext != nil {
			ctx = ctx.parentContext
		}
		for ; ctx != nil && c.globalSetFlags[name] == false; ctx = ctx.parentContext {
			ctx.flagSet.Visit(func(f *flag.Flag) {
				c.globalSetFlags[f.Name] = true
			})
		}
	}
	return c.globalSetFlags[name]
}

func (c *Context) FlagNames() (names []string) {
	for _, flag := range c.Command.Flags {
		name := strings.Split(flag.getName(), ",")[0]
		if name == "help" {
			continue
		}
		names = append(names, name)
	}
	return
}

func (c *Context) GlobalFlagNames() (names []string) {
	for _, flag := range c.App.Flags {
		name := strings.Split(flag.getName(), ",")[0]
		if name == "help" || name == "version" {
			continue
		}
		names = append(names, name)
	}
	return
}

func (c *Context) Parent() *Context {
	return c.parentContext
}

func (c *Context) Set(name, value string) error {
	c.setFlags = nil
	return c.flagSet.Set(name, value)
}

type Args []string

func (c *Context) Args() Args {
	args := Args(c.flagSet.Args())
	return args
}

func (a Args) Get(n int) string {
	if len(a) > n {
		return a[n]
	}
	return ""
}

func (a Args) First() string {
	return a.Get(0)
}

func (a Args) Tail() []string {
	if len(a) >= 2 {
		return []string(a)[1:]
	}
	return []string{}
}

func (a Args) Present() bool {
	return len(a) != 0
}

func (a Args) Swap(from, to int) error {
	if from >= len(a) || to >= len(a) {
		return errors.New("index out of range")
	}
	a[from], a[to] = a[to], a[from]
	return nil
}

func (a Args) Len() int {
	return len(a)
}

func lookupGlobalFlagSet(name string, ctx *Context) *flag.FlagSet {
	if ctx.parentContext != nil {
		ctx = ctx.parentContext
	}
	for ; ctx != nil; ctx = ctx.parentContext {
		if f := ctx.flagSet.Lookup(name); f != nil {
			return ctx.flagSet
		}
	}
	return nil
}

func lookupInt(name string, set *flag.FlagSet) int {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.Atoi(f.Value.String())
		if err != nil {
			return 0
		}
		return val
	}
	return 0
}

func lookupDuration(name string, set *flag.FlagSet) time.Duration {
	f := set.Lookup(name)
	if f != nil {
		val, err := time.ParseDuration(f.Value.String())
		if err == nil {
			return val
		}
	}
	return 0
}

func lookupFloat64(name string, set *flag.FlagSet) float64 {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.ParseFloat(f.Value.String(), 64)
		if err != nil {
			return 0
		}
		return val
	}
	return 0
}

func lookupString(name string, set *flag.FlagSet) string {
	f := set.Lookup(name)
	if f != nil {
		return f.Value.String()
	}
	return ""
}

func lookupStringSlice(name string, set *flag.FlagSet) []string {
	f := set.Lookup(name)
	if f != nil {
		return (f.Value.(*StringSlice)).Value()

	}
	return nil
}

func lookupIntSlice(name string, set *flag.FlagSet) []int {
	f := set.Lookup(name)
	if f != nil {
		return (f.Value.(*IntSlice)).Value()

	}
	return nil
}

func lookupGeneric(name string, set *flag.FlagSet) interface{} {
	f := set.Lookup(name)
	if f != nil {
		return f.Value
	}
	return nil
}

func lookupBool(name string, set *flag.FlagSet) bool {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			return false
		}
		return val
	}
	return false
}

func lookupBoolT(name string, set *flag.FlagSet) bool {
	f := set.Lookup(name)
	if f != nil {
		val, err := strconv.ParseBool(f.Value.String())
		if err != nil {
			return true
		}
		return val
	}
	return false
}

func copyFlag(name string, ff *flag.Flag, set *flag.FlagSet) {
	switch ff.Value.(type) {
	case *StringSlice:
	default:
		set.Set(name, ff.Value.String())
	}
}

func normalizeFlags(flags []Flag, set *flag.FlagSet) error {
	visited := make(map[string]bool)
	set.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	for _, f := range flags {
		parts := strings.Split(f.getName(), ",")
		if len(parts) == 1 {
			continue
		}
		var ff *flag.Flag
		for _, name := range parts {
			name = strings.Trim(name, " ")
			if visited[name] {
				if ff != nil {
					return errors.New("Cannot use two forms of the same flag: " + name + " " + ff.Name)
				}
				ff = set.Lookup(name)
			}
		}
		if ff == nil {
			continue
		}
		for _, name := range parts {
			name = strings.Trim(name, " ")
			if !visited[name] {
				copyFlag(name, ff, set)
			}
		}
	}
	return nil
}

var BashCompletionFlag = BoolFlag{
	Name: "generate-bash-completion",
}

var VersionFlag = BoolFlag{
	Name:  "version, v",
	Usage: "print the version",
}

var HelpFlag = BoolFlag{
	Name:  "help, h",
	Usage: "show help",
}

type Flag interface {
	fmt.Stringer
	Apply(*flag.FlagSet)
	getName() string
}

func flagSet(name string, flags []Flag) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)

	for _, f := range flags {
		f.Apply(set)
	}
	return set
}

func eachName(longName string, fn func(string)) {
	parts := strings.Split(longName, ",")
	for _, name := range parts {
		name = strings.Trim(name, " ")
		fn(name)
	}
}

type Generic interface {
	Set(value string) error
	String() string
}

type GenericFlag struct {
	Name   string
	Value  Generic
	Usage  string
	EnvVar string
}

func (f GenericFlag) String() string {
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s%s \"%v\"\t%v", prefixFor(f.Name), f.Name, f.Value, f.Usage))
}

func (f GenericFlag) Apply(set *flag.FlagSet) {
	val := f.Value
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				val.Set(envVal)
				break
			}
		}
	}
	eachName(f.Name, func(name string) {
		set.Var(f.Value, name, f.Usage)
	})
}

func (f GenericFlag) getName() string {
	return f.Name
}

type StringSlice []string

func (f *StringSlice) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (f *StringSlice) String() string {
	return fmt.Sprintf("%s", *f)
}

func (f *StringSlice) Value() []string {
	return *f
}

type StringSliceFlag struct {
	Name   string
	Value  *StringSlice
	Usage  string
	EnvVar string
}

func (f StringSliceFlag) String() string {
	firstName := strings.Trim(strings.Split(f.Name, ",")[0], " ")
	pref := prefixFor(firstName)
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s [%v]\t%v", prefixedNames(f.Name), pref+firstName+" option "+pref+firstName+" option", f.Usage))
}

func (f StringSliceFlag) Apply(set *flag.FlagSet) {
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				newVal := &StringSlice{}
				for _, s := range strings.Split(envVal, ",") {
					s = strings.TrimSpace(s)
					newVal.Set(s)
				}
				f.Value = newVal
				break
			}
		}
	}
	eachName(f.Name, func(name string) {
		if f.Value == nil {
			f.Value = &StringSlice{}
		}
		set.Var(f.Value, name, f.Usage)
	})
}

func (f StringSliceFlag) getName() string {
	return f.Name
}

type IntSlice []int

func (f *IntSlice) Set(value string) error {
	tmp, err := strconv.Atoi(value)
	if err != nil {
		return err
	} else {
		*f = append(*f, tmp)
	}
	return nil
}

func (f *IntSlice) String() string {
	return fmt.Sprintf("%d", *f)
}

func (f *IntSlice) Value() []int {
	return *f
}

type IntSliceFlag struct {
	Name   string
	Value  *IntSlice
	Usage  string
	EnvVar string
}

func (f IntSliceFlag) String() string {
	firstName := strings.Trim(strings.Split(f.Name, ",")[0], " ")
	pref := prefixFor(firstName)
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s [%v]\t%v", prefixedNames(f.Name), pref+firstName+" option "+pref+firstName+" option", f.Usage))
}

func (f IntSliceFlag) Apply(set *flag.FlagSet) {
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				newVal := &IntSlice{}
				for _, s := range strings.Split(envVal, ",") {
					s = strings.TrimSpace(s)
					err := newVal.Set(s)
					if err != nil {
						fmt.Fprintf(os.Stderr, err.Error())
					}
				}
				f.Value = newVal
				break
			}
		}
	}
	eachName(f.Name, func(name string) {
		if f.Value == nil {
			f.Value = &IntSlice{}
		}
		set.Var(f.Value, name, f.Usage)
	})
}

func (f IntSliceFlag) getName() string {
	return f.Name
}

type BoolFlag struct {
	Name   string
	Usage  string
	EnvVar string
}

func (f BoolFlag) String() string {
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s\t%v", prefixedNames(f.Name), f.Usage))
}

func (f BoolFlag) Apply(set *flag.FlagSet) {
	val := false
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				envValBool, err := strconv.ParseBool(envVal)
				if err == nil {
					val = envValBool
				}
				break
			}
		}
	}
	eachName(f.Name, func(name string) {
		set.Bool(name, val, f.Usage)
	})
}

func (f BoolFlag) getName() string {
	return f.Name
}

type BoolTFlag struct {
	Name   string
	Usage  string
	EnvVar string
}

// String returns a readable representation of this value (for usage defaults)
func (f BoolTFlag) String() string {
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s\t%v", prefixedNames(f.Name), f.Usage))
}

func (f BoolTFlag) Apply(set *flag.FlagSet) {
	val := true
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				envValBool, err := strconv.ParseBool(envVal)
				if err == nil {
					val = envValBool
					break
				}
			}
		}
	}
	eachName(f.Name, func(name string) {
		set.Bool(name, val, f.Usage)
	})
}

func (f BoolTFlag) getName() string {
	return f.Name
}

type StringFlag struct {
	Name   string
	Value  string
	Usage  string
	EnvVar string
}

func (f StringFlag) String() string {
	var fmtString string
	fmtString = "%s %v\t%v"

	if len(f.Value) > 0 {
		fmtString = "%s \"%v\"\t%v"
	} else {
		fmtString = "%s %v\t%v"
	}
	return withEnvHint(f.EnvVar, fmt.Sprintf(fmtString, prefixedNames(f.Name), f.Value, f.Usage))
}

func (f StringFlag) Apply(set *flag.FlagSet) {
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				f.Value = envVal
				break
			}
		}
	}
	eachName(f.Name, func(name string) {
		set.String(name, f.Value, f.Usage)
	})
}

func (f StringFlag) getName() string {
	return f.Name
}

type IntFlag struct {
	Name   string
	Value  int
	Usage  string
	EnvVar string
}

func (f IntFlag) String() string {
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s \"%v\"\t%v", prefixedNames(f.Name), f.Value, f.Usage))
}

func (f IntFlag) Apply(set *flag.FlagSet) {
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				envValInt, err := strconv.ParseInt(envVal, 0, 64)
				if err == nil {
					f.Value = int(envValInt)
					break
				}
			}
		}
	}
	eachName(f.Name, func(name string) {
		set.Int(name, f.Value, f.Usage)
	})
}

func (f IntFlag) getName() string {
	return f.Name
}

type DurationFlag struct {
	Name   string
	Value  time.Duration
	Usage  string
	EnvVar string
}

func (f DurationFlag) String() string {
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s \"%v\"\t%v", prefixedNames(f.Name), f.Value, f.Usage))
}

func (f DurationFlag) Apply(set *flag.FlagSet) {
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				envValDuration, err := time.ParseDuration(envVal)
				if err == nil {
					f.Value = envValDuration
					break
				}
			}
		}
	}
	eachName(f.Name, func(name string) {
		set.Duration(name, f.Value, f.Usage)
	})
}

func (f DurationFlag) getName() string {
	return f.Name
}

type Float64Flag struct {
	Name   string
	Value  float64
	Usage  string
	EnvVar string
}

func (f Float64Flag) String() string {
	return withEnvHint(f.EnvVar, fmt.Sprintf("%s \"%v\"\t%v", prefixedNames(f.Name), f.Value, f.Usage))
}

func (f Float64Flag) Apply(set *flag.FlagSet) {
	if f.EnvVar != "" {
		for _, envVar := range strings.Split(f.EnvVar, ",") {
			envVar = strings.TrimSpace(envVar)
			if envVal := os.Getenv(envVar); envVal != "" {
				envValFloat, err := strconv.ParseFloat(envVal, 10)
				if err == nil {
					f.Value = float64(envValFloat)
				}
			}
		}
	}
	eachName(f.Name, func(name string) {
		set.Float64(name, f.Value, f.Usage)
	})
}

func (f Float64Flag) getName() string {
	return f.Name
}

func prefixFor(name string) (prefix string) {
	if len(name) == 1 {
		prefix = "-"
	} else {
		prefix = "--"
	}
	return
}

func prefixedNames(fullName string) (prefixed string) {
	parts := strings.Split(fullName, ",")
	for i, name := range parts {
		name = strings.Trim(name, " ")
		prefixed += prefixFor(name) + name
		if i < len(parts)-1 {
			prefixed += ", "
		}
	}
	return
}

func withEnvHint(envVar, str string) string {
	envText := ""
	if envVar != "" {
		envText = fmt.Sprintf(" [$%s]", strings.Join(strings.Split(envVar, ","), ", $"))
	}
	return str + envText
}

var AppHelpTemplate = `NAME:
   {{.Name}} - {{.Usage}}

USAGE:
   {{.HelpName}} {{if .Flags}}[global options]{{end}}{{if .Commands}} command [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}
   {{if .Version}}
VERSION:
   {{.Version}}
   {{end}}{{if len .Authors}}
AUTHOR(S):
   {{range .Authors}}{{ . }}{{end}}
   {{end}}{{if .Commands}}
COMMANDS:
   {{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
   {{end}}{{end}}{{if .Flags}}
GLOBAL OPTIONS:
   {{range .Flags}}{{.}}
   {{end}}{{end}}{{if .Copyright }}
COPYRIGHT:
   {{.Copyright}}
   {{end}}
`

var CommandHelpTemplate = `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}}{{if .Flags}} [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{if .Description}}

DESCRIPTION:
   {{.Description}}{{end}}{{if .Flags}}

OPTIONS:
   {{range .Flags}}{{.}}
   {{end}}{{ end }}
`

var SubcommandHelpTemplate = `NAME:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} command{{if .Flags}} [command options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}

COMMANDS:
   {{range .Commands}}{{join .Names ", "}}{{ "\t" }}{{.Usage}}
   {{end}}{{if .Flags}}
OPTIONS:
   {{range .Flags}}{{.}}
   {{end}}{{end}}
`

var helpCommand = Command{
	Name:      "help",
	Aliases:   []string{"h"},
	Usage:     "Shows a list of commands or help for one command",
	ArgsUsage: "[command]",
	Action: func(c *Context) error {
		args := c.Args()
		if args.Present() {
			ShowCommandHelp(c, args.First())
		} else {
			ShowAppHelp(c)
		}
		return nil
	},
}

var helpSubcommand = Command{
	Name:      "help",
	Aliases:   []string{"h"},
	Usage:     "Shows a list of commands or help for one command",
	ArgsUsage: "[command]",
	Action: func(c *Context) error {
		args := c.Args()
		if args.Present() {
			ShowCommandHelp(c, args.First())
		} else {
			ShowSubcommandHelp(c)
		}
		return nil
	},
}

type helpPrinter func(w io.Writer, templ string, data interface{})

var HelpPrinter helpPrinter = printHelp
var VersionPrinter = printVersion

func ShowAppHelp(c *Context) {
	HelpPrinter(c.App.Writer, AppHelpTemplate, c.App)
}

func DefaultAppComplete(c *Context) {
	for _, command := range c.App.Commands {
		for _, name := range command.Names() {
			fmt.Fprintln(c.App.Writer, name)
		}
	}
}

func ShowCommandHelp(ctx *Context, command string) {
	if command == "" {
		HelpPrinter(ctx.App.Writer, SubcommandHelpTemplate, ctx.App)
		return
	}

	for _, c := range ctx.App.Commands {
		if c.HasName(command) {
			HelpPrinter(ctx.App.Writer, CommandHelpTemplate, c)
			return
		}
	}

	if ctx.App.CommandNotFound != nil {
		ctx.App.CommandNotFound(ctx, command)
	} else {
		fmt.Fprintf(ctx.App.Writer, "No help topic for '%v'\n", command)
	}
}

func ShowSubcommandHelp(c *Context) {
	ShowCommandHelp(c, c.Command.Name)
}

func ShowVersion(c *Context) {
	VersionPrinter(c)
}

func printVersion(c *Context) {
	fmt.Fprintf(c.App.Writer, "%v version %v\n", c.App.Name, c.App.Version)
}

func ShowCompletions(c *Context) {
	a := c.App
	if a != nil && a.BashComplete != nil {
		a.BashComplete(c)
	}
}

func ShowCommandCompletions(ctx *Context, command string) {
	c := ctx.App.Command(command)
	if c != nil && c.BashComplete != nil {
		c.BashComplete(ctx)
	}
}

func printHelp(out io.Writer, templ string, data interface{}) {
	funcMap := template.FuncMap{
		"join": strings.Join,
	}

	w := tabwriter.NewWriter(out, 0, 8, 1, '\t', 0)
	t := template.Must(template.New("help").Funcs(funcMap).Parse(templ))
	err := t.Execute(w, data)
	if err != nil {
		panic(err)
	}
	w.Flush()
}

func checkVersion(c *Context) bool {
	if c.GlobalBool("version") || c.GlobalBool("v") || c.Bool("version") || c.Bool("v") {
		ShowVersion(c)
		return true
	}
	return false
}

func checkHelp(c *Context) bool {
	if c.GlobalBool("h") || c.GlobalBool("help") || c.Bool("h") || c.Bool("help") {
		ShowAppHelp(c)
		return true
	}
	return false
}

func checkCommandHelp(c *Context, name string) bool {
	if c.Bool("h") || c.Bool("help") {
		ShowCommandHelp(c, name)
		return true
	}
	return false
}

func checkSubcommandHelp(c *Context) bool {
	if c.GlobalBool("h") || c.GlobalBool("help") {
		ShowSubcommandHelp(c)
		return true
	}
	return false
}

func checkCompletions(c *Context) bool {
	if (c.GlobalBool(BashCompletionFlag.Name) || c.Bool(BashCompletionFlag.Name)) && c.App.EnableBashCompletion {
		ShowCompletions(c)
		return true
	}
	return false
}

func checkCommandCompletions(c *Context, name string) bool {
	if c.Bool(BashCompletionFlag.Name) && c.App.EnableBashCompletion {
		ShowCommandCompletions(c, name)
		return true
	}
	return false
}
