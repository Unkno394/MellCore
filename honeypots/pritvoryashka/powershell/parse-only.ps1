# Use the official PowerShell parser as a syntax frontend only. The resulting
# tree is serialized as inert data; user input is never executed by pwsh.
$ErrorActionPreference = 'Stop'

function Convert-Redirections($redirections) {
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($redirection in $redirections) {
        if ($redirection -is [System.Management.Automation.Language.FileRedirectionAst]) {
            $items.Add(@{
                target = $redirection.Location.Extent.Text
                append = [bool]$redirection.Append
            })
        } else {
            throw 'This PowerShell redirection is not available in the virtual shell.'
        }
    }
    return $items.ToArray()
}

function Convert-Statements($statements) {
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($statement in $statements) {
        if ($statement -is [System.Management.Automation.Language.PipelineAst]) {
            $elements = [System.Collections.Generic.List[object]]::new()
            foreach ($element in $statement.PipelineElements) {
                if ($element -is [System.Management.Automation.Language.CommandAst]) {
                    $words = [System.Collections.Generic.List[string]]::new()
                    foreach ($item in $element.CommandElements) {
                        # Extent.Text retains quoting and variable references so
                        # the Rust evaluator can apply the limited safe semantics.
                        if ($item -is [System.Management.Automation.Language.CommandParameterAst]) {
                            $words.Add('-' + $item.ParameterName)
                            if ($null -ne $item.Argument) { $words.Add($item.Argument.Extent.Text) }
                        } else {
                            $words.Add($item.Extent.Text)
                        }
                    }
                    $elements.Add(@{
                        kind = 'command'
                        words = @($words.ToArray())
                        redirections = @(Convert-Redirections $element.Redirections)
                    })
                } elseif ($element -is [System.Management.Automation.Language.CommandExpressionAst]) {
                    $elements.Add(@{
                        kind = 'expression'
                        text = $element.Expression.Extent.Text
                        redirections = @(Convert-Redirections $element.Redirections)
                    })
                } else {
                    throw 'This PowerShell pipeline element is not available in the virtual shell.'
                }
            }
            $items.Add(@{ kind = 'pipeline'; elements = @($elements.ToArray()) })
        } elseif ($statement -is [System.Management.Automation.Language.AssignmentStatementAst] -and $statement.Operator.ToString() -eq 'Equals') {
            $items.Add(@{ kind = 'assignment'; left = $statement.Left.Extent.Text; right = $statement.Right.Extent.Text })
        } elseif ($statement -is [System.Management.Automation.Language.IfStatementAst]) {
            $clauses = [System.Collections.Generic.List[object]]::new()
            foreach ($clause in $statement.Clauses) {
                $clauses.Add(@{ condition = $clause.Item1.Extent.Text; body = @(Convert-Statements $clause.Item2.Statements) })
            }
            $elseBody = @()
            if ($null -ne $statement.ElseClause) { $elseBody = @(Convert-Statements $statement.ElseClause.Statements) }
            $items.Add(@{ kind = 'if'; clauses = @($clauses.ToArray()); else_body = $elseBody })
        } elseif ($statement -is [System.Management.Automation.Language.ForEachStatementAst]) {
            $items.Add(@{
                kind = 'for_each'
                variable = $statement.Variable.Extent.Text
                expression = $statement.Condition.Extent.Text
                body = @(Convert-Statements $statement.Body.Statements)
            })
        } elseif ($statement -is [System.Management.Automation.Language.ForStatementAst]) {
            $initializer = ''
            $condition = ''
            $iterator = ''
            if ($null -ne $statement.Initializer) { $initializer = $statement.Initializer.Extent.Text }
            if ($null -ne $statement.Condition) { $condition = $statement.Condition.Extent.Text }
            if ($null -ne $statement.Iterator) { $iterator = $statement.Iterator.Extent.Text }
            $items.Add(@{
                kind = 'for'
                initializer = $initializer
                condition = $condition
                iterator = $iterator
                body = @(Convert-Statements $statement.Body.Statements)
            })
        } elseif ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            $parameters = [System.Collections.Generic.List[string]]::new()
            if ($null -ne $statement.Body.ParamBlock) {
                foreach ($parameter in $statement.Body.ParamBlock.Parameters) {
                    $parameters.Add($parameter.Name.VariablePath.UserPath)
                }
            }
            $bodyStatements = @()
            if ($null -ne $statement.Body.EndBlock) {
                $bodyStatements = @(Convert-Statements $statement.Body.EndBlock.Statements)
            }
            $items.Add(@{
                kind = 'function'
                name = $statement.Name
                parameters = @($parameters.ToArray())
                body = $bodyStatements
            })
        } elseif ($statement -is [System.Management.Automation.Language.ExitStatementAst]) {
            $items.Add(@{ kind = 'pipeline'; elements = @(@{ kind = 'command'; words = @('exit') }) })
        } else {
            throw 'This PowerShell statement is not available in the virtual shell.'
        }
    }
    return $items.ToArray()
}

while ($null -ne ($request = [Console]::In.ReadLine())) {
    $result = @{ error = $null; incomplete = $false; items = @() }
    try {
        $source = ConvertFrom-Json -InputObject $request -ErrorAction Stop
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput(
            $source, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count -gt 0) {
            $result.error = $parseErrors[0].Message
            $result.incomplete = [bool]$parseErrors[0].IncompleteInput
        } elseif ($null -eq $ast.EndBlock) {
            $result.error = 'Unsupported PowerShell input.'
        } else {
            $result.items = @(Convert-Statements $ast.EndBlock.Statements)
        }
    } catch {
        $result.error = $_.Exception.Message
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Compress -Depth 20))
    [Console]::Out.Flush()
}
