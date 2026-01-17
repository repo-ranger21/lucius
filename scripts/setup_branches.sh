#!/bin/bash
#
# Lucius Branch Setup Script
# This script sets up the core branches for the Lucius repository
#

set -e

echo "🌿 Lucius Git Branch Setup"
echo "=========================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}❌ Error: Not a git repository${NC}"
    exit 1
fi

echo "📍 Current repository: $(git remote get-url origin)"
echo "📍 Current branch: $(git branch --show-current)"
echo ""

# Function to create and push branch
create_and_push_branch() {
    local branch_name=$1
    local source_branch=$2

    echo -e "${YELLOW}Creating branch: $branch_name${NC}"

    # Check if branch already exists locally
    if git show-ref --verify --quiet refs/heads/$branch_name; then
        echo "  ✓ Branch already exists locally"
    else
        echo "  Creating from $source_branch..."
        git checkout $source_branch
        git checkout -b $branch_name
        echo "  ✓ Created $branch_name"
    fi

    # Push to remote
    echo "  Pushing to remote..."
    if git push -u origin $branch_name 2>&1; then
        echo -e "${GREEN}  ✅ Successfully pushed $branch_name${NC}"
    else
        echo -e "${RED}  ❌ Failed to push $branch_name${NC}"
        echo "  You may need to push this branch manually later"
    fi

    echo ""
}

# Main setup
echo "🚀 Setting up core branches..."
echo ""

# Ensure we have the latest from remote
echo "📥 Fetching latest from remote..."
git fetch origin
echo ""

# Check if main exists
if ! git show-ref --verify --quiet refs/heads/main; then
    if git show-ref --verify --quiet refs/remotes/origin/main; then
        echo "Creating local main from origin/main..."
        git checkout -b main --track origin/main
    else
        echo -e "${RED}❌ Error: main branch not found${NC}"
        exit 1
    fi
fi

# Create develop branch
create_and_push_branch "develop" "main"

# Create staging branch
create_and_push_branch "staging" "main"

# Return to main
git checkout main

echo ""
echo -e "${GREEN}✅ Branch setup complete!${NC}"
echo ""
echo "📋 Available branches:"
git branch -a | grep -E '(main|develop|staging)' || true
echo ""
echo "📚 Next steps:"
echo "  1. Set develop as default branch on GitHub"
echo "  2. Configure branch protection rules (see BRANCHING_STRATEGY.md)"
echo "  3. Set up CI/CD workflows for each branch"
echo "  4. Start development: git checkout develop"
echo ""
echo "📖 Read BRANCHING_STRATEGY.md for complete workflow guide"
